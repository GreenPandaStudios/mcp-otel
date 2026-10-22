FROM node:24.18.0-bookworm-slim
WORKDIR /app
COPY package.json health.js server.js ./
USER 1000:1000
CMD ["node","server.js"]
