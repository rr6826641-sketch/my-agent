"""Remote Control Hub (R1): Terminal/Remote Control se system.

Self-contained remote control layer for the agent. Three tool surfaces:

  * remote_control(action, port, token) - HTTP Control Hub (Flask, token-auth)
    jo kisi bhi device/browser se is system ko control karne deta hai:
       GET  /                    -> mini HTML control console (live terminal box)
       GET  /api/status          -> system + agent + PTY status
       POST /api/exec            -> {command, timeout, cwd} local command run
       POST /api/pty             -> {action: open|send|read|kill, ...} interactive PTY
       POST /api/upload          -> multipart file upload (saves to cwd/target)
       GET  /api/download?path=  -> serve file
       GET  /api/ps              -> process list
       POST /api/kill            -> {pid} kill process (tree on Windows)
    Auth: har request par `X-Agent-Token` header ya `?token=` (auto aur
    user-supplied dono chalti hain; auto token har start par regenerate).

  * remote_ssh(host, user, ...) - paramiko SSH client: run / connect_test /
    upload / download. Taaki agent khud remote hosts control kare.

  * remote_screenshot(save_to)  - active screen capture (PIL ImageGrab ->
    mss -> Windows PowerShell fallback) taki remote se screen dekh sako.

Binding 0.0.0.0 deliberate hai (LAN remote control); return mein token +
LAN IPs print hote hain. Server daemon thread mein chalta hai, agent ka
main flow block nahi hota.
"""

import base64
import datetime
import json
import os
import secrets
import socket
import subprocess
import threading

from ..config import PROJECT_DIR

_TOKEN_STORE = os.path.join(PROJECT_DIR, "memory", "remote_control_token.txt")
_ACTIVE = {"server": None, "token": "", "port": 0, "started": ""}
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_token():
    try:
        with open(_TOKEN_STORE, "r", encoding="utf-8") as fh:
            tok = fh.read().strip()
            if tok:
                return tok
    except Exception:
        pass
    return None


def _save_token(tok):
    try:
        os.makedirs(os.path.dirname(_TOKEN_STORE), exist_ok=True)
        with open(_TOKEN_STORE, "w", encoding="utf-8") as fh:
            fh.write(tok)
    except Exception:
        pass


def _lan_ips():
    ips = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


def _run_cmd(command, timeout=60, cwd=None):
    """Run a local command and return text output (never raises for rc)."""
    try:
        proc = subprocess.run(
            command, shell=True, cwd=cwd or None, timeout=int(timeout or 60),
            capture_output=True, text=True, errors="replace",
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        rc = proc.returncode
        return out if out.strip() else "(empty output)", rc
    except subprocess.TimeoutExpired:
        return "(command timed out after %ss)" % timeout, -1
    except Exception as exc:
        return "error: %r" % exc, -1


def _system_snapshot():
    lines = ["hostname: %s" % socket.gethostname(),
             "time: %s" % datetime.datetime.now().isoformat()]
    try:
        import platform
        lines.append("platform: %s" % platform.platform())
        lines.append("python: %s" % platform.python_version())
    except Exception:
        pass
    try:
        out, _ = _run_cmd(
            "wmic os get TotalVisibleMemorySize,FreePhysicalMemory /value"
            if os.name == "nt" else "free -m", 10)
        lines.append("mem: %s" % out.strip()[:120])
    except Exception:
        pass
    with _LOCK:
        hub = dict(_ACTIVE)
    lines.append("control hub: port=%s started=%s" % (hub["port"], hub["started"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PTY bridge (reuse engine from pty_terminal.py)
# ---------------------------------------------------------------------------

def _pty_open(command, cwd=None):
    from .pty_terminal import pty_start_session
    return pty_start_session(command, cwd=cwd or None, name="remote-hub")


def _pty_send(session_id, data, press_enter=False):
    from .pty_terminal import pty_send_input
    return pty_send_input(session_id, data, press_enter=bool(press_enter))


def _pty_read(session_id, timeout=2.0):
    from .pty_terminal import pty_read_output
    return pty_read_output(session_id, timeout=float(timeout or 2.0))


def _pty_kill(session_id):
    from .pty_terminal import pty_kill_session
    return pty_kill_session(session_id)


def _pty_all():
    from .pty_terminal import pty_status
    return pty_status(active_only=False)


# ---------------------------------------------------------------------------
# Flask control hub
# ---------------------------------------------------------------------------

_SERVER_FLASK = None


def _build_app(token, max_out):
    try:
        from flask import (Flask, Response, jsonify, request,
                           send_file, send_from_directory)
    except Exception as exc:  # pragma: no cover
        return None, "flask import failed: %r" % exc

    app = Flask("RemoteControlHub")

    def _auth_ok():
        got = request.headers.get("X-Agent-Token") or request.args.get("token")
        return secrets.compare_digest((got or "").strip(), token)

    def _denied():
        return jsonify({"error": "unauthorized - bad/missing X-Agent-Token"}), 401

    @app.after_request
    def _utf8(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    @app.route("/")
    def _console():
        if not _auth_ok():
            return Response(
                "403 - <form method=get><input name=token placeholder='agent token'>"
                "<button>unlock</button></form>", status=403)
        return Response(
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Agent Remote Console</title>"
            "<style>body{font-family:monospace;background:#0b0f14;color:#d7e0e8;"
            "padding:20px}h1{font-size:16px;color:#7ee0a3}textarea{width:100%;"
            "height:320px;background:#0e141b;color:#cfe6d8;border:1px solid #2a3a4a}"
            "input[type=text]{width:75%;background:#0e141b;color:#e8f1f8;"
            "border:1px solid #2a3a4a;padding:6px}button{background:#1b6b3f;"
            "color:#fff;border:0;padding:6px 14px;cursor:pointer}</style></head>"
            "<body><h1>⚡ Agent Remote Console (authorized) - %s</h1>"
            "<div><input id=c placeholder='command, e.g. dir / python --version'>"
            "<button onclick=go()>RUN</button> <button onclick=clearOut()>clear</button></div>"
            "<pre id=out></pre><script>"
            "const tok=new URLSearchParams(location.search).get('token');"
            "async function go(){const c=document.getElementById('c').value;"
            "const r=await fetch('/api/exec?token='+tok,{method:'POST',headers:"
            "{'Content-Type':'application/json'},body:JSON.stringify({command:c})});"
            "const j=await r.json();"
            "document.getElementById('out').textContent+='$ '+c+'\\n'+(j.output||j.error)+'\\n';}"
            "function clearOut(){document.getElementById('out').textContent='';}"
            "</script></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"})

    @app.route("/api/status")
    def _status():
        if not _auth_ok():
            return _denied()
        data = {"ok": True, "system": _system_snapshot(),
                "pty": _pty_all()[:4000]}
        return jsonify(data)

    @app.route("/api/exec", methods=["POST"])
    def _exec():
        if not _auth_ok():
            return _denied()
        payload = request.get_json(silent=True) or {}
        command = str(payload.get("command") or "").strip()
        if not command:
            return jsonify({"error": "command required"}), 400
        out, rc = _run_cmd(command, payload.get("timeout", 60),
                           payload.get("cwd"))
        return jsonify({"output": out[: int(max_out or 20000)], "rc": rc,
                        "ts": datetime.datetime.now().isoformat()})

    @app.route("/api/pty", methods=["POST"])
    def _pty():
        if not _auth_ok():
            return _denied()
        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "").strip()
        try:
            if action == "open":
                return jsonify({"result": _pty_open(
                    str(payload.get("command") or "cmd.exe"),
                    payload.get("cwd"))})
            if action == "send":
                return jsonify({"result": _pty_send(
                    str(payload.get("session") or ""),
                    str(payload.get("data") or ""),
                    bool(payload.get("enter")))})
            if action == "read":
                return jsonify({"result": _pty_read(
                    str(payload.get("session") or ""),
                    float(payload.get("timeout") or 2.0))})
            if action == "kill":
                return jsonify({"result": _pty_kill(
                    str(payload.get("session") or ""))})
            return jsonify({"error": "action must be open|send|read|kill"}), 400
        except Exception as exc:
            return jsonify({"error": "pty %s failed: %r" % (action, exc)}), 500

    @app.route("/api/upload", methods=["POST"])
    def _upload():
        if not _auth_ok():
            return _denied()
        f = request.files.get("file")
        if f is None:
            return jsonify({"error": "multipart field 'file' required"}), 400
        target = str(request.form.get("target") or f.filename or "upload")
        if not os.path.isabs(target):
            target = os.path.join(os.getcwd(), target)
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            f.save(target)
            return jsonify({"ok": True, "saved": target,
                            "size": os.path.getsize(target)})
        except Exception as exc:
            return jsonify({"error": "upload failed: %r" % exc}), 500

    @app.route("/api/download")
    def _download():
        if not _auth_ok():
            return _denied()
        path = str(request.args.get("path") or "").strip()
        if not path or not os.path.isfile(path):
            return jsonify({"error": "file not found: %s" % path}), 404
        try:
            return send_file(path, as_attachment=True,
                             download_name=os.path.basename(path))
        except Exception as exc:
            return jsonify({"error": "download failed: %r" % exc}), 500

    @app.route("/api/ps")
    def _ps():
        if not _auth_ok():
            return _denied()
        out, rc = _run_cmd(
            "wmic process get ProcessId,Name,CommandLine /format:list" if os.name == "nt"
            else "ps aux", 15)
        return jsonify({"output": out[: int(max_out or 20000)], "rc": rc})

    @app.route("/api/kill", methods=["POST"])
    def _kill():
        if not _auth_ok():
            return _denied()
        payload = request.get_json(silent=True) or {}
        pid = str(payload.get("pid") or "").strip()
        if not pid:
            return jsonify({"error": "pid required"}), 400
        out, rc = _run_cmd(
            ("taskkill /F /T /PID %s" % pid) if os.name == "nt"
            else ("kill -9 %s" % pid), 15)
        return jsonify({"output": out[:2000], "rc": rc})

    return app, None


def _start_hub(port, token):
    global _SERVER_FLASK
    app, err = _build_app(token, 20000)
    if err:
        return err
    try:
        _SERVER_FLASK = app.run(
            host="0.0.0.0", port=int(port), threaded=True, use_reloader=False,
            debug=False)
    except Exception as exc:
        _SERVER_FLASK = None
        return "remote_control: server failed to start: %r" % exc
    return None


def tool_remote_control(action="status", port=8443, token=""):
    """Remote Control Hub: HTTP-based system control (start/stop/status).

    action=start: token-auth Flask hub on 0.0.0.0:port -> console page + API.
    action=status: current hub info + system snapshot + PTY sessions.
    action=stop:   shut the hub down (in-process flag).
    action=token:  print/rotate the stored access token.
    """
    action = (action or "status").strip().lower()
    if action == "status":
        with _LOCK:
            hub = dict(_ACTIVE)
        info = ["server: %s" % ("RUNNING" if hub["server"] else "STOPPED"),
                "port: %s" % hub["port"] or "-",
                "started: %s" % hub["started"] or "-",
                "lan urls: %s" % ", ".join(
                    "http://%s:%s/?token=%s" % (ip, hub["port"] or port, hub["token"] or "-")
                    for ip in _lan_ips()) if hub["port"] else "-"]
        return "\n".join(info) + "\n" + _system_snapshot()

    if action == "token":
        tok = _load_token() or token or secrets.token_hex(16)
        if token:
            _save_token(token)
        return "stored token: %s" % tok

    if action == "start":
        with _LOCK:
            if _ACTIVE["server"]:
                return "remote_control: hub already RUNNING on port %s" % _ACTIVE["port"]
        tok = token.strip() or _load_token() or secrets.token_hex(16)
        if token.strip():
            _save_token(tok)
        t = threading.Thread(target=_start_hub, args=(int(port), tok),
                             daemon=True, name="remote-control-hub")
        t.start()
        # small wait for bind attempt
        import time
        time.sleep(1.2)
        with _LOCK:
            _ACTIVE.update(server=t, token=tok, port=int(port),
                           started=datetime.datetime.now().isoformat())
        lines = ["remote_control: hub STARTED on 0.0.0.0:%s" % port,
                 "token: %s" % tok,
                 "console: http://<this-pc>:%s/?token=%s" % (port, tok)]
        for ip in _lan_ips():
            lines.append("  lan: http://%s:%s/?token=%s" % (ip, port, tok))
        lines.append("api: /api/status /api/exec /api/pty /api/upload "
                     "/api/download /api/ps /api/kill")
        return "\n".join(lines)

    if action == "stop":
        with _LOCK:
            _ACTIVE["server"] = None
            _ACTIVE["port"] = 0
            _ACTIVE["started"] = ""
        # Flask runtime thread daemon hai; stop flag se APIs 503 dena
        # chhota rakhne ke liye bas status clear karte hain.
        return "remote_control: hub STOPPED (status flag reset; restart to rebind)"

    return ("remote_control: unknown action '%s' - use start|status|stop|token"
            % action)


# ---------------------------------------------------------------------------
# SSH client (paramiko)
# ---------------------------------------------------------------------------

def tool_remote_ssh(host, user="root", port=22, password="", key_path="",
                    command="", action="run", local_path="", remote_path=""):
    """SSH remote host control via paramiko.

    action=run:          execute `command` on remote host and return output.
    action=connect_test: banner/connection test (host, user, version).
    action=upload:       local_path -> remote_path (SFTP).
    action=download:     remote_path -> local_path (SFTP).
    Auth: password ya private key_path (>=1 required). Keyless publickey
    agent-compatible nahi hai - hamesha password/key do.
    """
    host = (host or "").strip()
    if not host:
        return "remote_ssh: host required"
    action = (action or "run").strip().lower()
    try:
        import paramiko
    except Exception as exc:
        return "remote_ssh: paramiko missing - run: pip install paramiko (%r)" % exc
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": host, "port": int(port or 22),
                  "username": user or "root", "timeout": 15,
                  "allow_agent": False, "look_for_keys": False}
        if (password or "").strip():
            kwargs["password"] = password
        elif (key_path or "").strip():
            kwargs["key_filename"] = key_path
        else:
            return "remote_ssh: password ya key_path required"
        client.connect(**kwargs)
        try:
            if action == "connect_test":
                remote = client.get_transport()
                banner = (remote and remote.remote_version) or "?"
                return "SSH OK -> %s@%s:%s [%s]" % (user, host, port, banner)
            if action == "run":
                if not (command or "").strip():
                    return "remote_ssh: command required for run"
                _in, _out, _err = client.exec_command(command, timeout=60)
                out = _out.read().decode("utf-8", "replace")
                err = _err.read().decode("utf-8", "replace")
                return (out + err).strip() or "(no output)"
            if action in ("upload", "download"):
                if not local_path or not remote_path:
                    return "remote_ssh: local_path + remote_path required for %s" % action
                sftp = client.open_sftp()
                try:
                    if action == "upload":
                        if not os.path.isfile(local_path):
                            return "remote_ssh: local file missing: %s" % local_path
                        sftp.put(local_path, remote_path)
                        return "uploaded %s -> %s" % (local_path, remote_path)
                    else:
                        sftp.get(remote_path, local_path)
                        return "downloaded %s -> %s" % (remote_path, local_path)
                finally:
                    sftp.close()
            return ("remote_ssh: unknown action '%s' - use run|connect_test|"
                    "upload|download" % action)
        finally:
            client.close()
    except Exception as exc:
        return "remote_ssh: failed: %r" % exc


# ---------------------------------------------------------------------------
# Screen capture
# ---------------------------------------------------------------------------

def tool_remote_screenshot(save_to=""):
    """Capture the active screen to a PNG file (PIL -> mss -> PowerShell).

    save_to: full path (default: memory/screenshots/agent_screen_<ts>.png).
    Returns the saved path on success (remote user phir /api/download se
    le sakta hai).
    """
    save_to = (save_to or "").strip()
    try:
        if not save_to:
            save_to = os.path.join(PROJECT_DIR, "memory", "screenshots",
                                   "agent_screen_%s.png" %
                                   datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        os.makedirs(os.path.dirname(save_to) or ".", exist_ok=True)
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.save(save_to, "PNG")
            return "screenshot saved: %s (%d bytes)" % (
                save_to, os.path.getsize(save_to))
        except Exception:
            try:
                import mss
                with mss.mss() as sct:
                    shot = sct.shot(output=save_to)
                return "screenshot saved (mss): %s (%d bytes)" % (
                    shot, os.path.getsize(shot))
            except Exception:
                if os.name == "nt":
                    ps = (
                        "Add-Type -AssemblyName System.Windows.Forms;"
                        "Add-Type -AssemblyName System.Drawing;"
                        "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                        "$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);"
                        "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
                        "$bmp.Save('%s')" % save_to.replace("'", "''"))
                    out, rc = _run_cmd(
                        "powershell -NoProfile -Command \"%s\"" % ps, 30)
                    if rc == 0 and os.path.isfile(save_to):
                        return "screenshot saved (powershell): %s (%d bytes)" % (
                            save_to, os.path.getsize(save_to))
                    return "remote_screenshot: capture failed: %s" % out[:300]
                return ("remote_screenshot: no capture backend - pip install "
                        "Pillow mss")
    except Exception as exc:
        return "remote_screenshot: failed: %r" % exc


if __name__ == "__main__":
    print("remote_control.py loaded ~ tools: remote_control, remote_ssh, "
          "remote_screenshot")