# RiseUp MCP

This add-on runs the official [RiseUp MCP server](https://github.com/riseup-oss/mcp) inside Home Assistant OS
and exposes it as a **remote MCP connector** for Claude (web, desktop and the mobile app).

Access is protected by OAuth 2.1: Claude registers itself automatically, and you approve it once by typing
the add-on's login password. Only Claude's official callback URLs are accepted. Tokens are stored hashed in
`/data`, and changing the login password disconnects every client.

## 1. Create a RiseUp token

Go to <https://input.riseup.co.il/developer/tokens>. Select every scope you want Claude to read (budget, bank
balances, mortgage, savings & investments, loans, benchmarks) and copy the token. It is shown only once. Tokens
expire after 30 days.

## 2. Expose the add-on over HTTPS

Claude connects from Anthropic's servers, so the add-on needs a public HTTPS address. The recommended way is
the **Cloudflared** add-on (add the repository `https://github.com/homeassistant-apps/repository`) with a domain
on Cloudflare. In its configuration, add:

```yaml
additional_hosts:
  - hostname: riseup.example.com
    service: http://HOSTNAME:8099
```

Replace `HOSTNAME` with this add-on's hostname, which is shown on its Info page (for example
`a1b2c3d4-riseup-mcp`). You do not need to open any port on your router.

## 3. Configure this add-on

| Option | Value |
|---|---|
| `riseup_pat` | The token from step 1 (`riseup_pat_…`) |
| `login_password` | A password of at least 12 characters. You type it once when connecting Claude |
| `public_url` | The address from step 2, e.g. `https://riseup.example.com` (without `/mcp`) |

Start the add-on and open its **Log** tab. It prints the connector URL, for example:

```
Connector URL to paste into Claude: https://riseup.example.com/ceAY0YULTt…/mcp
```

The long random part is generated on first start and stored in `/data`. Every endpoint lives under it, so
anyone scanning your hostname gets only `404 Not found`. Treat the URL as private.

## 4. Connect Claude

On claude.ai (web), go to **Settings → Connectors → Add custom connector**:

- Name: `RiseUp`
- URL: the full connector URL from the log
- Leave Advanced settings empty

Click **Connect**. A RiseUp login page opens. Enter the login password. The connector is then available in
the Claude mobile app too.

## Renewing the RiseUp token

When the RiseUp token expires, create a new one, paste it into `riseup_pat` and restart the add-on. Claude
stays connected.

## Security notes

- The RiseUp token is read-only and never leaves this add-on except to call `input.riseup.co.il`.
- All endpoints sit under a secret random path; the bare hostname returns 404.
- Five wrong passwords lock the login for 15 minutes.
- To disconnect every client, change `login_password` and restart.
