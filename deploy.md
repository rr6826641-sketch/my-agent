# Docker Deployment Guide

Run the AI Agent Web UI in a single container. The image is built on
`python:3.12-slim`, runs as a non-root user, and binds `0.0.0.0:8080`.

## Prerequisites

- Docker Engine 24+ (or Docker Desktop) with the compose plugin: `docker compose version`
- API access: copy `.env.example` to `.env` and set `AGENT_API_KEY` (plus
  `AGENT_BASE_URL` / `AGENT_MODEL` if you do not want the defaults).
  Without a key the UI starts in mock mode.

## Quick Start

```bash
# 1) Runtime state files must exist on the host BEFORE compose up,
#    otherwise Docker creates directories in their place.
cp config.example.json config.json
touch chats.json memory.json findings.jsonl tasks.json nvd_cache.json personas_custom.txt
mkdir -p rpg artifacts reports data memory

# 2) Secrets
cp .env.example .env      # then edit: add AGENT_API_KEY etc.

# 3) Build and start
docker compose up -d --build

# 4) Open the UI
http://localhost:8080
```

Stop / logs / rebuild:

```bash
docker compose down
docker compose logs -f
docker compose up -d --build     # rebuild after code changes
```

## Manual Build (without compose)

```bash
docker build -t my-agent .
docker run --rm -p 8080:8080 --env-file .env \
  -v "$PWD/config.json:/app/config.json" \
  -v "$PWD/chats.json:/app/chats.json" \
  -v "$PWD/memory.json:/app/memory.json" \
  -v "$PWD/findings.jsonl:/app/findings.jsonl" \
  -v "$PWD/tasks.json:/app/tasks.json" \
  -v "$PWD/nvd_cache.json:/app/nvd_cache.json" \
  -v "$PWD/personas_custom.txt:/app/personas_custom.txt" \
  -v "$PWD/rpg:/app/rpg" -v "$PWD/artifacts:/app/artifacts" \
  -v "$PWD/reports:/app/reports" -v "$PWD/data:/app/data" \
  -v "$PWD/memory:/app/memory" \
  my-agent
```

## Configuration

| Knob | Default | Notes |
|------|---------|-------|
| `PORT` | `8080` | Container listen port (compose sets it; change the host side in `ports:`) |
| `AGENT_API_KEY` | - | LLM API key, from `.env` (env_file). Never baked into the image |
| `AGENT_BASE_URL` / `AGENT_MODEL` | provider defaults | Override base URL / model |
| `config.json` | mounted | Runtime settings (`red_team_mode`, `auto`, persona, etc.); API key fields in the file are ignored |

## Persistence

All mutable state is bind-mounted from the project directory (see
`docker-compose.yml`): `config.json`, `chats.json`, `memory.json`,
`findings.jsonl`, `tasks.json`, `nvd_cache.json`, `personas_custom.txt`,
and the `rpg/ artifacts/ reports/ data/ memory/` directories.
Back up those host paths to back up the deployment.

## Security Notes

- The container runs as unprivileged user `agent` (non-root).
- The Web UI has **no authentication** - bind it to localhost only
  (`127.0.0.1:8080:8080` in `ports:`) unless you put a reverse proxy with
  auth (basic auth / TLS) in front of it.
- Secrets come from the environment (`.env` -> `env_file`); `.env` is
  excluded from the build context by `.dockerignore`.
