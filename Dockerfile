FROM node:24.18.0-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src ./src
COPY scripts ./scripts
USER 1000:1000
EXPOSE 8080
CMD ["node","src/main.js"]
