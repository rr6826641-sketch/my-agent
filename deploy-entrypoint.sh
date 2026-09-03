#!/bin/sh
# Container entrypoint: guarantee runtime files/dirs exist, then start the UI.
set -e
cd /app

# Default config from the shipped example if none was bind-mounted
[ -f config.json ] || cp config.example.json config.json

# Empty runtime state files (SQLite/JSON handled gracefully, but keep them present)
for f in chats.json memory.json findings.jsonl tasks.json nvd_cache.json personas_custom.txt; do
    [ -f "$f" ] || : > "$f"
done

# Runtime directories
for d in rpg artifacts reports data memory; do
    [ -d "$d" ] || mkdir -p "$d"
done

# PORT can override the listen port; host must stay 0.0.0.0 in a container
exec python webui.py --host 0.0.0.0 --port "${PORT:-8080}"
