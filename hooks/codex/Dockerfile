FROM node:24.18.0-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* && npm install -g @openai/codex@0.163.0
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["codex"]
