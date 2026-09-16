"""Desktop Automation Pack (R2): screen capture + clipboard + GUI recorder.

Three new surfaces on top of the Human Interface Kit (mouse/keyboard):

  * screen_capture(save_to, region) - take a PNG of the full screen or a
    region "x,y,w,h". Backends: PIL ImageGrab -> mss -> Windows PowerShell
    (System.Drawing). monitor mode ko mss chahiye.

  * clipboard(action, text) - Windows native clipboard via ctypes
    (CF_UNICODETEXT): get_text / set_text / clear. Non-Windows par
    tkinter -> xclip/pbpaste fallback.

  * gui_recorder(action, name, interval) - record real mouse + keyboard
    actions into a JSON timeline, phir gui_replay unhe wapas chala deta
    hai (Human Interface Kit primitives ke through).

      recording backend priority:
        1. pynput      - event-driven, exact (agar installed)
        2. win-poll    - Windows native 40Hz polling: GetCursorPos +
                        GetAsyncKeyState (moves/clicks/keys), zero deps

      replay: gui_replay(path, speed, dry_run) - timing gaps preserve
      karta hai (speed se scale), drags correctly (down -> move -> up).

Recordings: desktop_automation/recordings/rec_<ts>_<name>.json
Captures:  desktop_automation/captures/sc_<ts>.png

Saari returns JSON mein. Bounded: recorder sirf manual start/stop, koi
hidden/background capture nahi.
"""

import datetime
import json
import os
import platform
import re
import threading
import time

from ..config import PROJECT_DIR

from . import human_interface as HI

SYSTEM = platform.system()
_BASE = os.path.join(PROJECT_DIR, "desktop_automation")
_REC_DIR = os.path.join(_BASE, "recordings")
_CAP_DIR = os.path.join(_BASE, "captures")

_REC_STATE = {
    "active": False, "thread": None, "stop": threading.Event(),
    "t0": 0.0, "name": "", "events": [], "backend": "",
    "sampling_hz": 40, "_lock": threading.Lock(),
}


def _err(msg):
    return json.dumps({"error": msg}, ensure_ascii=False)


def _ps_run(script, timeout=30):
    """Run a PowerShell command, return (stdout, returncode)."""
    import subprocess
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=timeout)
        return (proc.stdout.decode("utf-8", "replace") +
                proc.stderr.decode("utf-8", "replace"), proc.returncode)
    except Exception as exc:
        return str(exc), -1


def _ok(**kw):
    kw["ok"] = True
    return json.dumps(kw, ensure_ascii=False, indent=2)


def _nameok(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name or "") or "rec"


# ---------------------------------------------------------------------------
# screen capture
# ---------------------------------------------------------------------------
def _parse_region(region):
    """'x,y,w,h' ('' = full screen) -> bbox tuple or None."""
    region = (region or "").strip()
    if not region:
        return None
    parts = [int(p) for p in re.split(r"[,\s]+", region) if p.strip()]
    if len(parts) == 4:
        x, y, w, h = parts
        return (x, y, x + w, y + h) if w > 0 and h > 0 else None
    return None


def tool_screen_capture(save_to="", region=""):
    """Capture the screen (full or region 'x,y,w,h') to a PNG file.
    Returns saved path + pixel size. Backends: PIL -> mss -> PowerShell."""
    try:
        save_to = (save_to or "").strip()
        if not save_to:
            os.makedirs(_CAP_DIR, exist_ok=True)
            save_to = os.path.join(
                _CAP_DIR, "sc_%s.png" %
                datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        os.makedirs(os.path.dirname(save_to) or ".", exist_ok=True)
        bbox = _parse_region(region)
        used = "PIL"
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab(bbox=bbox) if bbox else ImageGrab.grab(
                all_screens=True)
            img.save(save_to, "PNG")
        except Exception:
            used = "mss"
            import mss
            with mss.mss() as sct:
                if bbox:
                    mon = {"left": bbox[0], "top": bbox[1],
                           "width": bbox[2] - bbox[0],
                           "height": bbox[3] - bbox[1]}
                    sct.grab(mon).save(output=save_to)
                else:
                    sct.shot(output=save_to)
        if not os.path.isfile(save_to):
            raise RuntimeError("capture backend wrote no file")
        try:
            from PIL import Image
            w, h = Image.open(save_to).size
        except Exception:
            w = h = 0
        return _ok(saved=save_to, bytes=os.path.getsize(save_to),
                   size={"w": w, "h": h}, region=bbox, backend=used)
    except Exception as exc:
        # last resort: Windows PowerShell System.Drawing (full screen only)
        try:
            if os.name == "nt":
                ps = (
                    "Add-Type -AssemblyName System.Windows.Forms;"
                    "Add-Type -AssemblyName System.Drawing;"
                    "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                    "$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);"
                    "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                    "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
                    "$bmp.Save('%s')" % save_to.replace("'", "''"))
                out, rc = _ps_run(ps, 30)
                if rc == 0 and os.path.isfile(save_to):
                    return _ok(saved=save_to,
                               bytes=os.path.getsize(save_to),
                               size={"w": 0, "h": 0}, backend="powershell")
                return _err("screen_capture failed: %s" % out[:200])
        except Exception as exc2:
            return _err("screen_capture failed: %r (ps fallback: %r)"
                        % (exc, exc2))
        return _err("screen_capture failed: %r" % exc)


# ---------------------------------------------------------------------------
# clipboard
# ---------------------------------------------------------------------------
_CTYPES_READY = False


def _init_clip():
    """Set argtypes/restype once - 64-bit HGLOBAL truncation se bachne ke
    liye (ctypes default int restype pointer truncate kar deta hai)."""
    global _CTYPES_READY
    if _CTYPES_READY:
        return
    import ctypes
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.CloseClipboard.restype = ctypes.c_int
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    _CTYPES_READY = True


def _clip_get_text():
    """Read clipboard text (Windows native; fallbacks for other OSes)."""
    if os.name == "nt":
        import ctypes
        _init_clip()
        CF_UNICODETEXT = 13
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        if not user32.OpenClipboard(None):
            return None
        try:
            h = user32.GetClipboardData(CF_UNICODETEXT)
            if not h:
                return ""
            p = kernel32.GlobalLock(h)
            if not p:
                return ""
            try:
                return ctypes.wstring_at(p)
            finally:
                kernel32.GlobalUnlock(h)
        finally:
            user32.CloseClipboard()
    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        try:
            return root.clipboard_get()
        finally:
            root.destroy()
    except Exception:
        pass
    for cmd in (["xclip", "-selection", "clipboard", "-o"],
                ["xsel", "--clipboard", "--output"],
                ["pbpaste"]):
        try:
            import subprocess
            out = subprocess.run(cmd, capture_output=True, timeout=5)
            if out.returncode == 0:
                return out.stdout.decode("utf-8", "replace")
        except Exception:
            continue
    return None


def _clip_set_text(text):
    """Set clipboard text. Windows: CF_UNICODETEXT via GlobalAlloc."""
    text = str(text)
    if os.name == "nt":
        import ctypes
        _init_clip()
        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        GMEM_ZEROINIT = 0x0040
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_unicode_buffer(text)
        size = ctypes.sizeof(buf)
        h = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size)
        if not h:
            return False
        p = kernel32.GlobalLock(h)
        if p:
            ctypes.memmove(p, buf, size)
            kernel32.GlobalUnlock(h)
        if not user32.OpenClipboard(None):
            kernel32.GlobalFree(h)
            return False
        try:
            user32.EmptyClipboard()
            if not user32.SetClipboardData(CF_UNICODETEXT, h):
                kernel32.GlobalFree(h)  # ownership nahi liya
                return False
            return True  # system ab h ka malik hai
        finally:
            user32.CloseClipboard()
    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
            return True
        finally:
            root.destroy()
    except Exception:
        pass
    import subprocess
    try:
        subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(),
                       timeout=5, check=True)
        return True
    except Exception:
        return False


def _clip_clear():
    if os.name == "nt":
        import ctypes
        _init_clip()
        user32 = ctypes.windll.user32
        if not user32.OpenClipboard(None):
            return False
        try:
            user32.EmptyClipboard()
            return True
        finally:
            user32.CloseClipboard()
    return _clip_set_text("")


def tool_clipboard(action="get_text", text=""):
    """Clipboard control. action = get_text | set_text | clear.
    get_text sirf length/literal type batata hai (content nahi), set_text
    ke full content milta hai jab text page se aata hai."""
    try:
        action = (action or "get_text").strip().lower()
        if action == "get_text":
            val = _clip_get_text()
            if val is None:
                return _err("clipboard read failed (no backend)")
            return _ok(action="get_text", length=len(val),
                       preview=val[:60] if val else "")
        if action == "set_text":
            if text is None or text == "":
                return _err("text required for set_text")
            ok = _clip_set_text(text)
            return _ok(action="set_text", set=ok, characters=len(text))
        if action == "clear":
            ok = _clip_clear()
            return _ok(action="clear", cleared=ok)
        return _err("action must be get_text|set_text|clear")
    except Exception as exc:
        return _err("clipboard failed: %r" % exc)


# ---------------------------------------------------------------------------
# GUI recorder
# ---------------------------------------------------------------------------
# VK codes scanned by the win-poll backend (canonical names = HI._VK_MAP keys)
_POLL_VKS = [0x08, 0x09, 0x0D, 0x1B, 0x20, 0x25, 0x26, 0x27, 0x28,
             0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
             0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
             0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
             0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
             0x59, 0x5A, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
             0x77, 0x78, 0x79, 0x7A, 0x7B]
_MODIFIER_VKS = [0x10, 0x11, 0x12, 0x5B, 0x5C]
_BTN_VKS = ((0x01, "left"), (0x02, "right"), (0x04, "middle"))


def _vk_to_name(vk):
    rev = {}
    for name, code in HI._VK_MAP.items():
        rev.setdefault(code, name)
    return rev.get(vk, "")


def _emit(state, etype, **kw):
    ev = {"t": round(time.time() - state["t0"], 3), "type": etype}
    ev.update(kw)
    state["events"].append(ev)


def _poll_worker(state):
    """Windows native polling backend: moves (>=2px), click down/up,
    key press/release. ~interval Hz."""
    try:
        import ctypes
        HI._load_win32()
        user32 = ctypes.windll.user32
        keys = _POLL_VKS + _MODIFIER_VKS
        prev_keys = {vk: False for vk in keys}
        prev_btns = {vk: False for vk, _ in _BTN_VKS}
        prev_pos = None
        while not state["stop"].is_set():
            x, y = HI._mouse_pos_win()
            if prev_pos is None or abs(x - prev_pos[0]) + abs(y - prev_pos[1]) >= 2:
                _emit(state, "move", x=x, y=y)
                prev_pos = (x, y)
            for vk in keys:
                pressed = bool(user32.GetAsyncKeyState(vk) & 0x8000)
                if pressed != prev_keys[vk]:
                    name = _vk_to_name(vk)
                    if name:
                        _emit(state, "key", action="press" if pressed else
                              "release", key=name)
                    prev_keys[vk] = pressed
            for vk, bname in _BTN_VKS:
                pressed = bool(user32.GetAsyncKeyState(vk) & 0x8000)
                if pressed != prev_btns[vk]:
                    cx, cy = HI._mouse_pos_win()
                    _emit(state, "down" if pressed else "up", button=bname,
                          x=cx, y=cy)
                    prev_btns[vk] = pressed
            time.sleep(1.0 / max(4, int(state["sampling_hz"] or 40)))
    except Exception:
        pass
    finally:
        state["stop"].set()


def _pn_listeners(state):
    """pynput event-driven backend (if installed)."""
    from pynput import keyboard, mouse

    def on_move(x, y):
        _emit(state, "move", x=x, y=y)

    def on_click(x, y, button, pressed):
        b = {"left": "left", "right": "right", "middle": "middle"}.get(
            button.name, "left")
        _emit(state, "down" if pressed else "up", button=b, x=x, y=y)

    def on_scroll(x, y, dx, dy):
        _emit(state, "scroll", x=x, y=y, dx=dx, dy=dy)

    def on_press(key):
        name = _pn_key_name(key)
        if name:
            _emit(state, "key", action="press", key=name)

    def on_release(key):
        name = _pn_key_name(key)
        if name:
            _emit(state, "key", action="release", key=name)

    ms = mouse.Listener(on_move=on_move, on_click=on_click,
                        on_scroll=on_scroll)
    kb = keyboard.Listener(on_press=on_press, on_release=on_release)
    state["listeners"] = [ms, kb]
    ms.start()
    kb.start()
    while not state["stop"].wait(0.2):
        pass
    ms.stop()
    kb.stop()
    for ln in (ms, kb):
        try:
            ln.join(timeout=2)
        except Exception:
            pass


def _pn_key_name(key):
    from pynput.keyboard import Key
    try:
        if hasattr(key, "char") and key.char:
            c = key.char.lower()
            return _vk_to_name_name(c) or c
    except Exception:
        pass
    rev = {v: k for k, v in {
        "esc": Key.esc, "enter": Key.enter, "tab": Key.tab,
        "space": Key.space, "backspace": Key.backspace,
        "delete": Key.delete, "up": Key.up, "down": Key.down,
        "left": Key.left, "right": Key.right, "home": Key.home,
        "end": Key.end, "insert": Key.insert,
    }.items()}
    return rev.get(key, "")


def _vk_to_name_name(c):
    # single-char or digit keys are fine as-is (HI accepts them)
    return c if re.fullmatch(r"[a-z0-9]", c) else ""


def tool_gui_recorder(action="status", name="", interval=40):
    """GUI action recorder. action = start | stop | status.
    Records real mouse/keyboard into JSON timeline (pynput if available,
    else Windows native 40Hz polling - zero deps)."""
    try:
        action = (action or "status").strip().lower()
        st = _REC_STATE
        if action == "start":
            with st["_lock"]:
                if st["active"]:
                    return _err("recorder already running (%s)" % st["name"])
                st["stop"] = threading.Event()
                st["t0"] = time.time()
                st["name"] = _nameok(name)
                st["events"] = []
                st["sampling_hz"] = int(interval or 40)
                try:
                    import pynput  # noqa: F401
                    backend = "pynput"
                except Exception:
                    backend = "win-poll" if SYSTEM == "Windows" else "none"
                if backend == "none":
                    return _err("no recording backend - install pynput")
                st["backend"] = backend
                fn = _pn_listeners if backend == "pynput" else _poll_worker
                st["thread"] = threading.Thread(
                    target=fn, args=(st,), daemon=True, name="gui-recorder")
                st["thread"].start()
                st["active"] = True
            return _ok(action="start", recording=st["name"],
                       backend=st["backend"], sampling_hz=st["sampling_hz"],
                       started=datetime.datetime.now().isoformat(timespec="seconds"),
                       note="Bounded: manual stop se hi file banti hai")
        if action == "stop":
            with st["_lock"]:
                if not st["active"]:
                    return _err("no recorder running")
                st["stop"].set()
                th = st["thread"]
                st["active"] = False
            if th:
                th.join(timeout=3)
            events = list(st["events"])
            dur = round(st["t0"] and (time.time() - st["t0"]), 3) \
                if st["t0"] else 0.0
            os.makedirs(_REC_DIR, exist_ok=True)
            path = os.path.join(
                _REC_DIR, "rec_%s_%s.json" %
                (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), st["name"]))
            payload = {
                "version": 1, "backend": st["backend"],
                "started": datetime.datetime.fromtimestamp(
                    st["t0"]).isoformat(timespec="seconds") if st["t0"] else "",
                "duration_s": dur, "screen": _screen_size_dict(),
                "events": events,
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=1)
            counts = {}
            for ev in events:
                counts[ev["type"]] = counts.get(ev["type"], 0) + 1
            st["events"] = []
            st["t0"] = 0.0
            return _ok(action="stop", saved=path, events=len(events),
                       duration_s=dur, by_type=counts)
        if action == "status":
            recs = []
            if os.path.isdir(_REC_DIR):
                for fn in sorted(os.listdir(_REC_DIR)):
                    if fn.endswith(".json"):
                        recs.append(fn)
            return _ok(action="status", active=st["active"],
                       current=st["name"] if st["active"] else "",
                       backend=st["backend"],
                       recordings=sorted(recs, reverse=True)[:20])
        return _err("action must be start|stop|status")
    except Exception as exc:
        return _err("gui_recorder failed: %r" % exc)


def _screen_size_dict():
    try:
        w = HI._load_win32()
        sw, sh = HI._screen_size_win(w)
        return {"w": sw, "h": sh}
    except Exception:
        return {"w": 0, "h": 0}


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------
def _raw_button(button, down):
    b = HI._backend()
    if b == "sendinput":
        return HI._sendinput_mouse_button(button, "down" if down else "up")
    try:
        if b == "pyautogui":
            pg = HI._pg()
            (pg.mouseDown if down else pg.mouseUp)(
                button={"left": "left", "right": "right"}.get(button, "left"))
            return True
        if b == "pynput":
            mouse, _ = HI._pn()
            c = mouse.Controller()
            btn = {"left": mouse.Button.left, "right": mouse.Button.right,
                   "middle": mouse.Button.middle}.get(button.lower(),
                                                      mouse.Button.left)
            (c.press if down else c.release)(btn)
            return True
    except Exception:
        pass
    return False


def _raw_key(key, down):
    b = HI._backend()
    if b == "sendinput":
        return HI._sendinput_key(key, not down)
    try:
        if b == "pyautogui":
            pg = HI._pg()
            (pg.keyDown if down else pg.keyUp)(HI._pg_key(key))
            return True
        if b == "pynput":
            _, kb = HI._pn()
            c = kb.Controller()
            (c.press if down else c.release)(HI._pn_key(key))
            return True
    except Exception:
        pass
    return False


def _replay_events(events, speed=1.0, dry_run=False):
    """Replay an event list through Human Interface primitives."""
    speed = max(0.1, float(speed or 1.0))
    prev_t = 0.0
    counts = {}
    done = 0
    for ev in events:
        t = float(ev.get("t", 0) or 0)
        if not dry_run:
            gap = (t - prev_t) / speed
            if gap > 0:
                time.sleep(min(gap, 1.0))
        prev_t = t
        etype = ev.get("type")
        counts[etype] = counts.get(etype, 0) + 1
        if dry_run:
            done += 1
            continue
        try:
            if etype == "move":
                HI._mouse_move(ev["x"], ev["y"], absolute=True)
                time.sleep(0.002)
            elif etype in ("down", "up"):
                _raw_button(ev.get("button", "left"), etype == "down")
            elif etype == "scroll":
                dy = int(ev.get("dy", 0) or 0)
                if dy == 0:
                    dx = int(ev.get("dx", 0) or 0)
                    amount = max(1, abs(dx) // 120)
                    direction = "down" if dx < 0 else "up"
                    HI._mouse_scroll(amount, direction)
                else:
                    HI._mouse_scroll(max(1, abs(dy) // 120),
                                     "down" if dy < 0 else "up")
            elif etype == "key":
                _raw_key(ev.get("key", ""), ev.get("action") == "press")
            done += 1
        except Exception:
            continue
    return done, counts


def tool_gui_replay(path="", speed=1.0, dry_run=False):
    """Replay a recorded GUI timeline (JSON from gui_recorder) using the
    Human Interface Kit. speed = playback multiplier, dry_run = validate
    only (no real input injected)."""
    try:
        path = (path or "").strip()
        if not path or not os.path.isfile(path):
            return _err("recording path required or not found: %r" % path)
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        events = payload.get("events")
        if not isinstance(events, list):
            return _err("invalid recording: no events list")
        if dry_run:
            bad = []
            for i, ev in enumerate(events):
                etype = ev.get("type")
                if etype in ("move",) and ("x" not in ev or "y" not in ev):
                    bad.append(i)
                elif etype in ("down", "up") and "button" not in ev:
                    bad.append(i)
                elif etype == "key" and "key" not in ev:
                    bad.append(i)
            return _ok(dry_run=True, validated=len(bad) == 0, events=len(events),
                       bad_indices=bad[:10], backend=payload.get("backend"),
                       duration_s=payload.get("duration_s"),
                       file=path,
                       note="no input injected (dry_run)")
        done, counts = _replay_events(events, speed, dry_run=False)
        return _ok(replayed=done, total=len(events), by_type=counts,
                   speed=speed, file=path)
    except Exception as exc:
        return _err("gui_replay failed: %r" % exc)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def tool_desktop_status():
    """Desktop Automation Pack status: capture/clipboard/recorder
    capabilities, screen size, existing recordings & captures."""
    try:
        caps = {"PIL": False, "mss": False, "pynput": False}
        for mod in ("PIL", "mss", "pynput"):
            try:
                __import__(mod)
                caps[mod] = True
            except Exception:
                caps[mod] = False
        recs = []
        if os.path.isdir(_REC_DIR):
            recs = sorted(os.listdir(_REC_DIR), reverse=True)[:20]
        caps_count = 0
        if os.path.isdir(_CAP_DIR):
            caps_count = len([f for f in os.listdir(_CAP_DIR)
                              if f.endswith(".png")])
        return _ok(system=SYSTEM,
                   backends={"clipboard": "native-ctypes" if SYSTEM == "Windows"
                             else "tkinter/xclip",
                             "recorder": _REC_STATE["backend"] or
                             ("pynput" if caps["pynput"] else
                              ("win-poll" if SYSTEM == "Windows" else "none")),
                             "capture": "PIL" if caps["PIL"] else
                             ("mss" if caps["mss"] else "powershell")},
                   installed=caps, screen=_screen_size_dict(),
                   recordings=recs, captures= caps_count,
                   dirs={"recordings": _REC_DIR, "captures": _CAP_DIR},
                   tools=["screen_capture", "clipboard", "gui_recorder",
                          "gui_replay", "desktop_status"])
    except Exception as exc:
        return _err("desktop_status failed: %r" % exc)


if __name__ == "__main__":
    print("desktop_automation.py loaded ~ tools: screen_capture, clipboard, "
          "gui_recorder, gui_replay, desktop_status")
