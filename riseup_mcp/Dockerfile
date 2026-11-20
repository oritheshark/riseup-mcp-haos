# Uses the official Node image directly (multi-arch: amd64/aarch64).
# The Supervisor's BUILD_FROM base image has no Node, so it is ignored on purpose.
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY app/server.mjs ./

EXPOSE 8099
CMD ["node", "/app/server.mjs"]
