// RiseUp MCP gateway for Home Assistant OS.
// Runs the official @riseup-oss/mcp stdio server as a child process and exposes it
// over Streamable HTTP, protected by a minimal single-user OAuth 2.1 server
// (Dynamic Client Registration + PKCE S256 + password login), so it can be added
// as a custom connector in Claude (web, desktop, mobile).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// ---------- configuration ----------
const DATA_DIR = process.env.DATA_DIR || '/data';
const OPTIONS_FILE = path.join(DATA_DIR, 'options.json');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const PORT = Number(process.env.PORT || 8099);

function loadOptions() {
  let opts = {};
  try { opts = JSON.parse(fs.readFileSync(OPTIONS_FILE, 'utf8')); } catch { /* fall back to env */ }
  return {
    riseupPat: (opts.riseup_pat ?? process.env.RISEUP_PAT ?? '').trim(),
    loginPassword: opts.login_password ?? process.env.LOGIN_PASSWORD ?? '',
    publicUrl: (opts.public_url ?? process.env.PUBLIC_URL ?? '').trim().replace(/\/+$/, ''),
    extraRedirectUris: opts.extra_redirect_uris ?? [],
  };
}

const opts = loadOptions();
const fatal = (msg) => { console.error(`[riseup-mcp] CONFIG ERROR: ${msg}`); process.exit(1); };
if (!opts.riseupPat.startsWith('riseup_pat_')) fatal('riseup_pat is missing or does not start with "riseup_pat_".');
if (opts.loginPassword.length < 12) fatal('login_password must be at least 12 characters.');
let publicUrl;
try { publicUrl = new URL(opts.publicUrl); } catch { fatal('public_url must be a full URL, e.g. https://riseup.example.com'); }
if (publicUrl.protocol !== 'https:') fatal('public_url must start with https://');

const BASE = opts.publicUrl;
const RESOURCE = `${BASE}/mcp`;
const ALLOWED_REDIRECTS = new Set([
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback',
  ...opts.extraRedirectUris,
]);

const ACCESS_TTL = 60 * 60 * 1000;            // 1 hour
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days
const CODE_TTL = 2 * 60 * 1000;               // 2 minutes
const MAX_CLIENTS = 20;

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const b64url = (buf) => buf.toString('base64url');
const randomToken = () => b64url(crypto.randomBytes(32));

// ---------- persistent state ----------
// Tokens are stored only as SHA-256 hashes. Changing login_password revokes everything.
const passwordFingerprint = sha256(`fp:${opts.loginPassword}`);
let state = { passwordFingerprint, clients: {}, accessTokens: {}, refreshTokens: {} };
try {
  const saved = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  if (saved.passwordFingerprint === passwordFingerprint) state = saved;
  else console.log('[riseup-mcp] login_password changed: all existing sessions revoked.');
} catch { /* first run */ }

function saveState() {
  const now = Date.now();
  for (const [k, v] of Object.entries(state.accessTokens)) if (v.exp < now) delete state.accessTokens[k];
  for (const [k, v] of Object.entries(state.refreshTokens)) if (v.exp < now) delete state.refreshTokens[k];
  const tmp = `${STATE_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
}
saveState();

const authCodes = new Map(); // in memory only, short-lived

// ---------- brute-force protection (global: single user) ----------
let failedLogins = [];
let lockedUntil = 0;
function loginLocked() { return Date.now() < lockedUntil; }
function recordFailure() {
  const now = Date.now();
  failedLogins = failedLogins.filter((t) => now - t < 15 * 60 * 1000);
  failedLogins.push(now);
  if (failedLogins.length >= 5) {
    lockedUntil = now + 15 * 60 * 1000;
    failedLogins = [];
    console.warn('[riseup-mcp] 5 failed logins: login locked for 15 minutes.');
  }
}
function passwordOk(candidate) {
  const a = Buffer.from(sha256(`pw:${candidate}`));
  const b = Buffer.from(sha256(`pw:${opts.loginPassword}`));
  return crypto.timingSafeEqual(a, b);
}

// ---------- upstream RiseUp MCP (stdio child) ----------
const require = createRequire(import.meta.url);
const riseupEntry = path.join(path.dirname(require.resolve('@riseup-oss/mcp/package.json')), 'dist', 'index.js');

let upstream = null;
let upstreamConnecting = null;
async function getUpstream() {
  if (upstream) return upstream;
  if (upstreamConnecting) return upstreamConnecting;
  upstreamConnecting = (async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [riseupEntry],
      env: { PATH: process.env.PATH || '/usr/bin:/bin', RISEUP_PAT: opts.riseupPat },
      stderr: 'inherit',
    });
    const client = new Client({ name: 'riseup-haos-gateway', version: '0.1.0' });
    transport.onclose = () => { console.warn('[riseup-mcp] upstream exited; will restart on next request.'); upstream = null; };
    await client.connect(transport);
    upstream = client;
    return client;
  })();
  try { return await upstreamConnecting; } finally { upstreamConnecting = null; }
}

function buildProxyServer() {
  const server = new Server({ name: 'riseup-mcp', version: '0.10.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async (req) => (await getUpstream()).listTools(req.params));
  server.setRequestHandler(CallToolRequestSchema, async (req) => (await getUpstream()).callTool(req.params));
  return server;
}

// ---------- HTTP ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

const oauthError = (res, status, error, description) =>
  res.status(status).json({ error, ...(description ? { error_description: description } : {}) });

app.get('/', (_req, res) => res.type('text').send('RiseUp MCP gateway is running.'));

const protectedResourceMetadata = (_req, res) => res.json({
  resource: RESOURCE,
  authorization_servers: [BASE],
  bearer_methods_supported: ['header'],
  resource_name: 'RiseUp',
});
app.get('/.well-known/oauth-protected-resource', protectedResourceMetadata);
app.get('/.well-known/oauth-protected-resource/mcp', protectedResourceMetadata);

const asMetadata = (_req, res) => res.json({
  issuer: BASE,
  authorization_endpoint: `${BASE}/authorize`,
  token_endpoint: `${BASE}/token`,
  registration_endpoint: `${BASE}/register`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
  scopes_supported: ['riseup'],
});
app.get('/.well-known/oauth-authorization-server', asMetadata);
app.get('/.well-known/openid-configuration', asMetadata);

// Dynamic Client Registration (RFC 7591) — only Claude's callback URLs are accepted.
app.post('/register', (req, res) => {
  const redirectUris = req.body?.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris required');
  const bad = redirectUris.filter((u) => !ALLOWED_REDIRECTS.has(u));
  if (bad.length) return oauthError(res, 400, 'invalid_redirect_uri', `redirect URI not allowed: ${bad.join(', ')}`);
  const clientId = `c_${randomToken()}`;
  const record = {
    client_id: clientId,
    client_name: String(req.body.client_name || 'MCP client').slice(0, 100),
    redirect_uris: redirectUris,
    created: Date.now(),
  };
  const ids = Object.keys(state.clients).sort((a, b) => state.clients[a].created - state.clients[b].created);
  while (ids.length >= MAX_CLIENTS) delete state.clients[ids.shift()];
  state.clients[clientId] = record;
  saveState();
  res.status(201).json({
    ...record,
    client_id_issued_at: Math.floor(record.created / 1000),
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
});

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function validateAuthorizeParams(p) {
  const client = state.clients[p.client_id];
  if (!client) return 'Unknown client. Remove the connector in Claude and add it again.';
  if (!client.redirect_uris.includes(p.redirect_uri)) return 'redirect_uri does not match the registered client.';
  if (p.response_type !== 'code') return 'response_type must be "code".';
  if (!p.code_challenge || p.code_challenge_method !== 'S256') return 'PKCE (S256) is required.';
  return null;
}

function loginPage(p, message) {
  const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'resource', 'scope', 'response_type']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(p[k])}">`).join('');
  const clientName = esc(state.clients[p.client_id]?.client_name || 'MCP client');
  return `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>RiseUp MCP</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f5f7;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;padding:28px;border-radius:14px;box-shadow:0 2px 12px #0002;width:min(92vw,360px)}
h1{font-size:20px;margin:0 0 6px}p{color:#555;font-size:14px}input[type=password]{width:100%;box-sizing:border-box;padding:12px;font-size:16px;border:1px solid #ccc;border-radius:8px}
button{margin-top:14px;width:100%;padding:12px;font-size:16px;border:0;border-radius:8px;background:#1f6feb;color:#fff}.err{color:#b00020}</style></head>
<body><form class="card" method="post" action="/authorize"><h1>חיבור RiseUp</h1>
<p><b>${clientName}</b> מבקש גישת קריאה לנתוני RiseUp שלך.</p>${message ? `<p class="err">${esc(message)}</p>` : ''}
${hidden}<input type="password" name="password" placeholder="סיסמת התוסף" autofocus required autocomplete="current-password">
<button type="submit">אישור</button></form></body></html>`;
}

app.get('/authorize', (req, res) => {
  const p = req.query;
  const err = validateAuthorizeParams(p);
  if (err) return res.status(400).type('text').send(err);
  res.set('Cache-Control', 'no-store').set('X-Frame-Options', 'DENY').type('html').send(loginPage(p));
});

app.post('/authorize', (req, res) => {
  const p = req.body || {};
  const err = validateAuthorizeParams(p);
  if (err) return res.status(400).type('text').send(err);
  res.set('Cache-Control', 'no-store').set('X-Frame-Options', 'DENY');
  if (loginLocked()) return res.status(429).type('html').send(loginPage(p, 'יותר מדי ניסיונות. נסה שוב בעוד 15 דקות.'));
  if (!passwordOk(String(p.password || ''))) {
    recordFailure();
    console.warn(`[riseup-mcp] failed login from ${req.ip}`);
    return res.status(401).type('html').send(loginPage(p, 'סיסמה שגויה.'));
  }
  failedLogins = [];
  const code = randomToken();
  authCodes.set(sha256(code), {
    client_id: p.client_id,
    redirect_uri: p.redirect_uri,
    code_challenge: p.code_challenge,
    exp: Date.now() + CODE_TTL,
  });
  const target = new URL(p.redirect_uri);
  target.searchParams.set('code', code);
  if (p.state) target.searchParams.set('state', p.state);
  console.log('[riseup-mcp] authorization granted.');
  res.redirect(302, target.toString());
});

function issueTokens(clientId) {
  const access = randomToken();
  const refresh = randomToken();
  const now = Date.now();
  state.accessTokens[sha256(access)] = { client_id: clientId, exp: now + ACCESS_TTL };
  state.refreshTokens[sha256(refresh)] = { client_id: clientId, exp: now + REFRESH_TTL };
  saveState();
  return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL / 1000, refresh_token: refresh, scope: 'riseup' };
}

app.post('/token', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const p = req.body || {};
  if (p.grant_type === 'authorization_code') {
    const key = sha256(String(p.code || ''));
    const rec = authCodes.get(key);
    authCodes.delete(key); // single use
    if (!rec || rec.exp < Date.now()) return oauthError(res, 400, 'invalid_grant', 'code invalid or expired');
    if (rec.client_id !== p.client_id || rec.redirect_uri !== p.redirect_uri) return oauthError(res, 400, 'invalid_grant', 'client or redirect mismatch');
    const challenge = b64url(crypto.createHash('sha256').update(String(p.code_verifier || '')).digest());
    if (challenge !== rec.code_challenge) return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed');
    return res.json(issueTokens(rec.client_id));
  }
  if (p.grant_type === 'refresh_token') {
    const key = sha256(String(p.refresh_token || ''));
    const rec = state.refreshTokens[key];
    if (!rec || rec.exp < Date.now()) return oauthError(res, 400, 'invalid_grant', 'refresh token invalid or expired');
    if (p.client_id && p.client_id !== rec.client_id) return oauthError(res, 400, 'invalid_grant', 'client mismatch');
    delete state.refreshTokens[key]; // rotate
    return res.json(issueTokens(rec.client_id));
  }
  return oauthError(res, 400, 'unsupported_grant_type');
});

// ---------- MCP endpoint ----------
function requireBearer(req, res, next) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  const rec = m && state.accessTokens[sha256(m[1].trim())];
  if (!rec || rec.exp < Date.now()) {
    const meta = `${BASE}/.well-known/oauth-protected-resource/mcp`;
    res.set('WWW-Authenticate', m
      ? `Bearer error="invalid_token", resource_metadata="${meta}"`
      : `Bearer resource_metadata="${meta}"`);
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

app.post('/mcp', requireBearer, async (req, res) => {
  const server = buildProxyServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on('close', () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error('[riseup-mcp] request failed:', e?.message || e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
  }
});
app.all('/mcp', requireBearer, (_req, res) => res.status(405).set('Allow', 'POST').json({ error: 'method_not_allowed' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[riseup-mcp] listening on :${PORT}; public MCP URL: ${RESOURCE}`);
  getUpstream().then(() => console.log('[riseup-mcp] RiseUp MCP server started.')).catch((e) => console.error('[riseup-mcp] upstream failed to start:', e?.message || e));
});
