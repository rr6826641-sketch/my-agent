# AI Agent Web UI - production container
# Build:  docker build -t my-agent .
# Run:    docker run --rm -p 8080:8080 --env-file .env my-agent

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first for layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY webui.py agent.py ./
COPY ai_agent/ ./ai_agent/
COPY templates/ ./templates/
COPY static/ ./static/
COPY system_prompt.txt system_prompt_pro.txt ./

# Defaults + entrypoint
COPY config.example.json ./
COPY .env.example ./
COPY deploy-entrypoint.sh ./deploy-entrypoint.sh
RUN chmod +x ./deploy-entrypoint.sh

# Non-root runtime user; entrypoint ensures runtime files exist and are writable
RUN groupadd -r agent \
 && useradd -r -g agent -d /app -s /usr/sbin/nologin agent \
 && chown -R agent:agent /app

USER agent

EXPOSE 8080

# Bind-mounted files (config.json, chats.json, ...) and directories
# (rpg/, artifacts/, reports/, data/, memory/) persist state; see deploy.md
ENTRYPOINT ["sh", "./deploy-entrypoint.sh"]
