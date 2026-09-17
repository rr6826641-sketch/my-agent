#!/usr/bin/env python3
"""MyAgentUltra - Desktop App (tray launcher for the AI Agent Web UI).

- Starts the Flask webui in-process on a free local port (prefers 8080).
- Auto-opens the default browser.
- Sits in the system tray: Open Browser / Data Folder / Restart / Quit.
- Single-instance (second launch just opens the browser).
- Frozen build (PyInstaller onefile): wants a tray icon; seeds missing
  personas_custom.txt / data/ from the bundle next to the EXE.

Usage:
    python myagent_app.py [--port 8080] [--no-browser] [--mock]
    python myagent_app.py --trayless    # no tray icon (console mode)
"""

import argparse
import ctypes
import json
import os
import shutil
import socket
import sys
import threading
import time
import webbrowser

APP_NAME = "MyAgentUltra"
PORT_FILE = ".myagent_port"
LOG_FILE = "app.log"
FROZEN = bool(getattr(sys, "frozen", False))
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
CODE_DIR = getattr(sys, "_MEIPASS", BASE_DIR) if FROZEN else BASE_DIR

_server = None  # {url, stop_event}


def log(msg):
    try:
        with open(os.path.join(BASE_DIR, LOG_FILE), "a", encoding="utf-8") as fh:
            fh.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _single_instance():
    """Windows named mutex; returns True if we own it (first instance)."""
    if not sys.platform.startswith("win"):
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        name = "Global\\MyAgentUltra_SingleInstance"
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            return True
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return False
        # keep handle alive for process lifetime
        _single_instance.handle = handle
        return True
    except Exception:
        return True


def _free_port(preferred, tries=50):
    for port in list(range(preferred, preferred + tries)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            pass
        finally:
            s.close()
    return 0


def _seed_data():
    """Copy bundled assets next to the EXE if missing (first run)."""
    if not FROZEN:
        return
    seeds = [
        ("personas_custom.txt", "personas_custom.txt"),
        ("data/cpe_template_index.json", "data/cpe_template_index.json"),
        ("data/uploads", "data/uploads"),
    ]
    for src_rel, dst_rel in seeds:
        src = os.path.join(CODE_DIR, src_rel.replace("/", os.sep))
        dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
        try:
            if os.path.isdir(src):
                os.makedirs(dst, exist_ok=True)
                continue
            if os.path.isfile(src) and not os.path.isfile(dst):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                log("seeded %s" % dst_rel)
        except Exception as exc:
            log("seed %s failed: %r" % (dst_rel, exc))


def start_server(port, mock=False):
    """Start webui Flask server in a background thread."""
    import webui

    try:
        webui._reload_state(mock_override=True if mock else None)
    except Exception as exc:
        log("reload_state failed (continuing): %r" % exc)

    stop_evt = threading.Event()

    def _run():
        try:
            webui.app.run(host="127.0.0.1", port=port, threaded=True,
                          debug=False, use_reloader=False)
        except Exception as exc:
            log("server thread error: %r" % exc)

    t = threading.Thread(target=_run, daemon=True, name="webui-server")
    t.start()

    # wait for readiness
    deadline = time.time() + 30
    while time.time() < deadline:
        if stop_evt.is_set():
            break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            s.connect(("127.0.0.1", port))
            s.close()
            break
        except OSError:
            time.sleep(0.25)
        finally:
            s.close()

    url = "http://127.0.0.1:%d" % port
    try:
        with open(os.path.join(BASE_DIR, PORT_FILE), "w", encoding="utf-8") as fh:
            fh.write(url)
    except Exception:
        pass
    log("server ready at %s" % url)
    return {"url": url, "thread": t, "stop": stop_evt}


def open_browser(url, every=False):
    try:
        if every or not os.environ.get("_MYAGENT_OPENED"):
            webbrowser.open(url)
            os.environ["_MYAGENT_OPENED"] = "1"
    except Exception as exc:
        log("browser open failed: %r" % exc)


def open_data_folder():
    try:
        os.startfile(BASE_DIR)  # noqa
    except Exception:
        pass


def run_tray(server, no_browser, mock):
    """Main-thread tray loop (pystray needs main thread on Windows)."""
    try:
        from PIL import Image, ImageDraw
        from pystray import Icon, Menu, MenuItem
    except Exception as exc:
        log("tray unavailable (%r) - running headless" % exc)
        # headless fallback: keep alive until killed
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        return

    img = Image.new("RGB", (64, 64), (10, 10, 14))
    d = ImageDraw.Draw(img)
    try:
        d.rounded_rectangle([6, 6, 58, 58], radius=14, fill=(208, 32, 48))
        d.ellipse([20, 16, 44, 40], fill=(255, 255, 255))
        d.rectangle([30, 44, 36, 56], fill=(255, 255, 255))
        d.ellipse([15, 12, 22, 19], fill=(255, 255, 255))
        d.ellipse([42, 12, 49, 19], fill=(255, 255, 255))
    except Exception:
        pass

    def on_open(icon, item):
        open_browser(server["url"], every=True)

    def on_data(icon, item):
        open_data_folder()

    def on_restart(icon, item):
        log("restart requested")
        icon.stop()
        if FROZEN:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            os.execv(sys.executable,
                     [sys.executable, os.path.abspath(__file__)] + sys.argv)

    def on_quit(icon, item):
        log("quit via tray")
        icon.stop()
        os._exit(0)

    try:
        sep = getattr(Menu, "SEPARATOR", None)
        menu = Menu(
            MenuItem("Open Agent (Browser)", on_open, default=True),
            MenuItem("Open Data Folder", on_data),
            MenuItem("Restart", on_restart),
            *([sep] if sep is not None else []),
            MenuItem("Quit", on_quit),
        )
        icon = Icon(APP_NAME, img, APP_NAME, menu)
        if not no_browser:
            open_browser(server["url"])
        log("tray running")
        icon.run()
    except Exception as exc:
        # tray must never kill the server: headless keep-alive fallback
        log("tray failed (%r) - headless keep-alive" % exc)
        if not no_browser:
            open_browser(server["url"])
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


def main():
    ap = argparse.ArgumentParser(description=APP_NAME + " Desktop App")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--trayless", action="store_true")
    args = ap.parse_args()

    log("=" * 50)
    log("start %s frozen=%s dir=%s" % (APP_NAME, FROZEN, BASE_DIR))

    _seed_data()

    if not _single_instance():
        log("another instance is running; opening browser")
        try:
            with open(os.path.join(BASE_DIR, PORT_FILE), encoding="utf-8") as fh:
                url = fh.read().strip()
                if url:
                    webbrowser.open(url)
        except Exception:
            pass
        time.sleep(2)
        return 0

    port = args.port if args.port else _free_port(8080)
    if args.port:
        actual = _free_port(args.port)
        if actual != args.port:
            port = actual if actual else _free_port(8080)
    else:
        port = _free_port(8080)

    server = start_server(port, mock=args.mock)
    res = {  # noqa: F841 - keep reference alive
        "url": server["url"], "port": port,
    }
    log("serving %s" % server["url"])

    if args.trayless or not sys.platform.startswith("win"):
        if not args.no_browser:
            webbrowser.open(server["url"])
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        return 0

    run_tray(server, args.no_browser, args.mock)
    return 0


if __name__ == "__main__":
    sys.exit(main())