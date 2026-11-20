ARG BUILD_FROM=node:22-alpine
FROM ${BUILD_FROM}

ENV NODE_ENV=production
WORKDIR /app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY app/server.mjs ./

EXPOSE 8099
CMD ["node", "/app/server.mjs"]
