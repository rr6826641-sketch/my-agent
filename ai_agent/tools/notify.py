"""Notification Engine: Telegram / Discord / generic webhook / findings digest.

Autonomous campaign alerts: agent kampaign chalata hai, critical discovery hoti
hai to ye tools live alerts bhejte hain - ab koi action silent nahi jata.

Tools:
- notify_telegram  -> Telegram Bot API sendMessage (bot token + chat id)
- notify_discord   -> Discord webhook (content POST)
- notify_webhook   -> generic JSON webhook (Slack-style {text: ...} or raw payload)
- notify_findings  -> findings.jsonl ka severity-filtered digest bana kar
                      chosen channel (telegram/discord/webhook) par bhejta hai

Secrets (arg se ya env/.env se): TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
DISCORD_WEBHOOK_URL. Bot tokens kabhi output mein full nahi dikhte - masked
hotay hain. Targets sirf authorized scoped engagements par.
"""

import json
import os

import requests

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
HTTP_TIMEOUT = 20

FINDINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "findings.jsonl",
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "info": "INFO"}


def _mask(secret):
    """Mask a token for display: first 6 + last 4 chars (never leak keys)."""
    secret = (secret or "").strip()
    if not secret:
        return ""
    if len(secret) <= 12:
        return "****"
    return "%s****%s" % (secret[:6], secret[-4:])


def _cfg(name, given):
    """Resolve a config value: explicit arg first, then env var."""
    value = (given or "").strip()
    if value:
        return value
    return (os.environ.get(name) or "").strip()


def _read_findings(limit=200):
    """Read latest findings.jsonl rows (newest kept)."""
    rows = []
    try:
        with open(FINDINGS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    row = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except (FileNotFoundError, OSError):
        return []
    return rows[-limit:]


# ---------------------------------------------------------------------------
# 1. Telegram
# ---------------------------------------------------------------------------

def tool_notify_telegram(bot_token="", chat_id="", message=""):
    """Send a live alert/message to a Telegram chat via the Bot API.

    - bot_token: Telegram bot token (or set TELEGRAM_BOT_TOKEN in .env)
    - chat_id: recipient chat id (or set TELEGRAM_CHAT_ID in .env)
    - message: text to send (up to ~3500 chars is safe)

    Returns delivery confirmation with message_id or a clear error. The bot
    token is masked in every response.
    """
    token = _cfg("TELEGRAM_BOT_TOKEN", bot_token)
    cid = _cfg("TELEGRAM_CHAT_ID", chat_id)
    msg = (message or "").strip()
    if not token:
        return ("notify_telegram: no bot token - pass bot_token or set "
                "TELEGRAM_BOT_TOKEN in .env")
    if not cid:
        return ("notify_telegram: no chat_id - pass chat_id or set "
                "TELEGRAM_CHAT_ID in .env")
    if not msg:
        return "notify_telegram: message is empty"
    try:
        resp = requests.post(
            "https://api.telegram.org/bot%s/sendMessage" % token,
            data={"chat_id": cid, "text": msg,
                  "disable_web_page_preview": "true",
                  "disable_notification": "false"},
            headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return ("notify_telegram: request failed (%r) - token %s"
                % (exc, _mask(token)))
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if resp.status_code == 200 and payload.get("ok"):
        mid = payload.get("result", {}).get("message_id")
        return ("notify_telegram: delivered (message_id=%s, chat=%s)"
                % (mid, cid))
    return ("notify_telegram: failed HTTP %d (%s) - token %s"
            % (resp.status_code, str(payload.get("description") or
                                     resp.text)[:200], _mask(token)))


# ---------------------------------------------------------------------------
# 2. Discord
# ---------------------------------------------------------------------------

def tool_notify_discord(webhook_url="", message="", username=""):
    """Send a message to a Discord channel via a webhook URL.

    - webhook_url: Discord webhook (or set DISCORD_WEBHOOK_URL in .env)
    - message: text content
    - username: optional override name (max 80 chars)

    Returns delivery confirmation (HTTP 2xx) or a clear error.
    """
    wh = _cfg("DISCORD_WEBHOOK_URL", webhook_url)
    msg = (message or "").strip()
    if not wh:
        return ("notify_discord: no webhook url - pass webhook_url or set "
                "DISCORD_WEBHOOK_URL in .env")
    if not msg:
        return "notify_discord: message is empty"
    payload = {"content": msg}
    if (username or "").strip():
        payload["username"] = (username or "").strip()[:80]
    try:
        resp = requests.post(wh, json=payload,
                             headers={"User-Agent": USER_AGENT},
                             timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "notify_discord: request failed: %r" % exc
    if 200 <= resp.status_code < 300:
        return "notify_discord: delivered (HTTP %d)" % resp.status_code
    return "notify_discord: failed HTTP %d (%s)" % (resp.status_code,
                                                    resp.text[:200])


# ---------------------------------------------------------------------------
# 3. Generic webhook
# ---------------------------------------------------------------------------

def tool_notify_webhook(url="", message="", payload="", method="POST"):
    """POST a JSON notification to any webhook/endpoint.

    - url: destination endpoint
    - message: text - sent as {"text": <message>} (Slack/Teams style)
    - payload: optional raw JSON string - sent as-is instead of {"text": ...}

    Returns delivery confirmation (HTTP 2xx) or a clear error.
    """
    if not (url or "").strip():
        return "notify_webhook: url is required"
    body = None
    if (payload or "").strip():
        try:
            body = json.loads(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            return "notify_webhook: payload is not valid JSON (%r)" % exc
    else:
        body = {"text": (message or "").strip()}
    if not body or (isinstance(body, dict) and not body):
        return "notify_webhook: nothing to send (message/payload empty)"
    try:
        resp = requests.post((url or "").strip(), json=body,
                             headers={"User-Agent": USER_AGENT},
                             timeout=HTTP_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "notify_webhook: request failed: %r" % exc
    if 200 <= resp.status_code < 300:
        return ("notify_webhook: delivered (%s, HTTP %d, %d bytes)"
                % ((url or "").strip(), resp.status_code, len(resp.content)))
    return "notify_webhook: failed HTTP %d (%s)" % (resp.status_code,
                                                    resp.text[:200])


# ---------------------------------------------------------------------------
# 4. Findings digest alert
# ---------------------------------------------------------------------------

def tool_notify_findings(channel="telegram", min_severity="high", limit=10,
                         bot_token="", chat_id="", webhook_url="",
                         include_summary=True):
    """Ship a severity-filtered digest of logged findings to a channel.

    - channel: telegram | discord | webhook
    - min_severity: critical | high | medium | low | info (filter floor)
    - limit: max findings to include in the alert (default 10)
    - bot_token / chat_id: for telegram
    - webhook_url: for discord/webhook
    - include_summary: prepend a count/summary header line

    Reads findings.jsonl, builds a compact digest and sends it through the
    chosen channel. If the store is empty or nothing meets the filter, it
    returns that instead of sending a useless message - no false alerts.
    """
    ch = (channel or "telegram").strip().lower()
    if ch not in ("telegram", "discord", "webhook"):
        return ("notify_findings: channel must be telegram | discord | "
                "webhook (got %r)" % (channel or ""))
    sev_min = (min_severity or "high").strip().lower()
    if sev_min not in SEVERITY_ORDER:
        return ("notify_findings: min_severity must be critical|high|medium|"
                "low|info (got %r)" % (min_severity or ""))
    try:
        limit = int(limit or 10)
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 25))

    rows = _read_findings()
    if not rows:
        return ("notify_findings: findings store empty (%s) - nothing to "
                "send" % FINDINGS_PATH)
    floor = SEVERITY_ORDER[sev_min]
    selected = [r for r in rows
                if SEVERITY_ORDER.get((r.get("severity") or "info").lower(),
                                      99) <= floor]
    if not selected:
        return ("notify_findings: no findings at severity >= %s - nothing "
                "to send" % sev_min)
    selected.sort(key=lambda r: SEVERITY_ORDER.get(
        (r.get("severity") or "info").lower(), 99))
    shown = selected[:limit]

    lines = []
    if include_summary:
        lines.append("[HackerAI Agent] Findings digest: %d @>=%s"
                     % (len(selected), sev_min))
    for r in shown:
        sev = (r.get("severity") or "info").lower()
        label = SEVERITY_LABEL.get(sev, sev.upper())
        title = (r.get("title") or "untitled").strip()
        asset = (r.get("asset") or "?").strip()
        fid = (r.get("id") or "").strip()
        left = title[:240]
        lines.append("- [%s] %s | %s | %s" % (label, left, asset, fid))
    if len(selected) > len(shown):
        lines.append("... and %d more (see findings.jsonl)"
                     % (len(selected) - len(shown)))
    msg = "\n".join(lines)
    if len(msg) > 3500:
        msg = msg[:3500] + "\n...(truncated)"

    if ch == "telegram":
        return tool_notify_telegram(bot_token=bot_token, chat_id=chat_id,
                                    message=msg)
    if ch == "discord":
        return tool_notify_discord(webhook_url=webhook_url, message=msg)
    return tool_notify_webhook(url=webhook_url, message=msg)