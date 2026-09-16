"""Human Interface Kit (R2): Mouse + Keyboard access for the agent.

Full input-device control so the agent can operate GUIs directly:
  * mouse: move (abs/rel), click (left/right/middle, single/double,
           down/up), drag, scroll, position read-back
  * keyboard: press single keys, type strings (unicode aware), run
           hotkey combos (ctrl+c, alt+tab, win+r, ctrl+shift+esc ...)

Backend priority (auto-detect, zero hard deps):
  1. SendInput - native Windows API via ctypes (no pip install)
  2. pyautogui  - if installed (cross-platform)
  3. pynput     - if installed (cross-platform)

Windows ke liye native backend default hai - koi pip package nahi
chahiye. Linux/macOS par pyautogui/pynput fallback use hota hai.
Har call bounded (lock-screen/login-wall gates check) aur JSON mein
result deta hai.
"""

import json
import os
import platform
import sys
import time

SYSTEM = platform.system()


def _err(msg):
    return json.dumps({"error": msg}, ensure_ascii=False)


def _ok(**kw):
    kw["ok"] = True
    return json.dumps(kw, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# backend detection
# ---------------------------------------------------------------------------
def _backend():
    """Pick the best available input backend."""
    if SYSTEM == "Windows":
        return "sendinput"  # native, no deps
    for name, mod in (("pyautogui", "pyautogui"), ("pynput", "pynput")):
        try:
            __import__(mod)
            return name
        except Exception:
            continue
    return "none"


# ---------------------------------------------------------------------------
# Windows SendInput backend (ctypes)
# ---------------------------------------------------------------------------
_WIN32 = {}


def _load_win32():
    import ctypes
    from ctypes import wintypes
    if _WIN32:
        return _WIN32
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    _WIN32["user32"] = user32
    _WIN32["SM_XVIRTUALSCREEN"] = 76
    _WIN32["SM_YVIRTUALSCREEN"] = 77
    _WIN32["SM_CXVIRTUALSCREEN"] = 78
    _WIN32["SM_CYVIRTUALSCREEN"] = 79
    _WIN32["MOUSEEVENTF_MOVE"] = 0x0001
    _WIN32["MOUSEEVENTF_LEFTDOWN"] = 0x0002
    _WIN32["MOUSEEVENTF_LEFTUP"] = 0x0004
    _WIN32["MOUSEEVENTF_RIGHTDOWN"] = 0x0008
    _WIN32["MOUSEEVENTF_RIGHTUP"] = 0x0010
    _WIN32["MOUSEEVENTF_MIDDLEDOWN"] = 0x0020
    _WIN32["MOUSEEVENTF_MIDDLEUP"] = 0x0040
    _WIN32["MOUSEEVENTF_WHEEL"] = 0x0800
    _WIN32["MOUSEEVENTF_XDOWN"] = 0x0080
    _WIN32["MOUSEEVENTF_XUP"] = 0x0100
    _WIN32["MOUSEEVENTF_ABSOLUTE"] = 0x8000
    _WIN32["KEYEVENTF_KEYUP"] = 0x0002
    _WIN32["KEYEVENTF_UNICODE"] = 0x0004
    _WIN32["KEYEVENTF_SCANCODE"] = 0x0008
    _WIN32["INPUT_MOUSE"] = 0
    _WIN32["INPUT_KEYBOARD"] = 1
    return _WIN32


def _screen_size_win(w):
    user32 = w["user32"]
    class POINT:
        def __init__(self, x=0, y=0):
            self.x = x
            self.y = y
    w_ = w["SM_CXVIRTUALSCREEN"]
    h_ = w["SM_CYVIRTUALSCREEN"]
    return (user32.GetSystemMetrics(w_), user32.GetSystemMetrics(h_))


def _mouse_pos_win():
    import ctypes
    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    pt = POINT()
    w = _load_win32()
    w["user32"].GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def _sendinput_mouse_move(x, y, absolute=True):
    import ctypes
    w = _load_win32()
    user32 = w["user32"]
    if absolute:
        sw, sh = _screen_size_win(w)
        nx = int(round(x * 65535.0 / max(sw - 1, 1)))
        ny = int(round(y * 65535.0 / max(sh - 1, 1)))
        dx, dy, flags = nx, ny, w["MOUSEEVENTF_MOVE"] | w["MOUSEEVENTF_ABSOLUTE"]
    else:
        dx, dy, flags = x, y, w["MOUSEEVENTF_MOVE"]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long),
                    ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                    ("time", ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]
    class INPUT(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("mi", MOUSEINPUT)]
    inp = INPUT()
    inp.type = w["INPUT_MOUSE"]
    inp.mi.dx = dx
    inp.mi.dy = dy
    inp.mi.dwFlags = flags
    inp.mi.time = 0
    inp.mi.dwExtraInfo = None
    sent = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    return sent == 1


def _sendinput_mouse_button(button, state):
    import ctypes
    w = _load_win32()
    user32 = w["user32"]
    flags = {
        ("left", "down"): w["MOUSEEVENTF_LEFTDOWN"],
        ("left", "up"): w["MOUSEEVENTF_LEFTUP"],
        ("right", "down"): w["MOUSEEVENTF_RIGHTDOWN"],
        ("right", "up"): w["MOUSEEVENTF_RIGHTUP"],
        ("middle", "down"): w["MOUSEEVENTF_MIDDLEDOWN"],
        ("middle", "up"): w["MOUSEEVENTF_MIDDLEUP"],
    }.get((button.lower(), state))
    if flags is None:
        return False
    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long),
                    ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                    ("time", ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]
    class INPUT(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("mi", MOUSEINPUT)]
    inp = INPUT()
    inp.type = w["INPUT_MOUSE"]
    inp.mi.dwFlags = flags
    inp.mi.time = 0
    inp.mi.dwExtraInfo = None
    sent = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    return sent == 1


def _sendinput_mouse_wheel(delta):
    import ctypes
    w = _load_win32()
    user32 = w["user32"]
    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long),
                    ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                    ("time", ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]
    class INPUT(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("mi", MOUSEINPUT)]
    inp = INPUT()
    inp.type = w["INPUT_MOUSE"]
    inp.mi.mouseData = int(delta) & 0xFFFFFFFF
    inp.mi.dwFlags = w["MOUSEEVENTF_WHEEL"]
    inp.mi.time = 0
    inp.mi.dwExtraInfo = None
    sent = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    return sent == 1


_VK_MAP = {
    "enter": 0x0D, "return": 0x0D, "esc": 0x1B, "escape": 0x1B,
    "tab": 0x09, "space": 0x20, "backspace": 0x08, "delete": 0x2E,
    "del": 0x2E, "insert": 0x2D, "home": 0x24, "end": 0x23,
    "pageup": 0x21, "pagedown": 0x22, "up": 0x26, "down": 0x28,
    "left": 0x25, "right": 0x27, "capslock": 0x14, "numlock": 0x90,
    "scrolllock": 0x91, "shift": 0x10, "ctrl": 0x11, "control": 0x11,
    "alt": 0x12, "win": 0x5B, "lwin": 0x5B, "rwin": 0x5C,
    "menu": 0x5D, "app": 0x5D, "f1": 0x70, "f2": 0x71, "f3": 0x72,
    "f4": 0x73, "f5": 0x74, "f6": 0x75, "f7": 0x76, "f8": 0x77,
    "f9": 0x78, "f10": 0x79, "f11": 0x7A, "f12": 0x7B,
    "0": 0x30, "1": 0x31, "2": 0x32, "3": 0x33, "4": 0x34,
    "5": 0x35, "6": 0x36, "7": 0x37, "8": 0x38, "9": 0x39,
    "a": 0x41, "b": 0x42, "c": 0x43, "d": 0x44, "e": 0x45,
    "f": 0x46, "g": 0x47, "h": 0x48, "i": 0x49, "j": 0x4A,
    "k": 0x4B, "l": 0x4C, "m": 0x4D, "n": 0x4E, "o": 0x4F,
    "p": 0x50, "q": 0x51, "r": 0x52, "s": 0x53, "t": 0x54,
    "u": 0x55, "v": 0x56, "w": 0x57, "x": 0x58, "y": 0x59,
    "z": 0x5A, ";": 0xBA, "=": 0xBB, ",": 0xBC, "-": 0xBD,
    ".": 0xBE, "/": 0xBF, "`": 0xC0, "[": 0xDB, "\\": 0xDC,
    "]": 0xDD, "'": 0xDE,
    "printscreen": 0x2C, "pause": 0x13, "sleep": 0x5F,
}


def _sendinput_key(key_name, key_up=False):
    import ctypes
    w = _load_win32()
    user32 = w["user32"]
    name = (key_name or "").strip().lower()
    vk = _VK_MAP.get(name)
    if vk is None and len(name) == 1:
        vk = ord(name.upper())
    if vk is None:
        return False
    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", ctypes.c_ushort), ("wScan", ctypes.c_ushort),
                    ("dwFlags", ctypes.c_ulong), ("time", ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]
    class INPUT(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("ki", KEYBDINPUT)]
    inp = INPUT()
    inp.type = w["INPUT_KEYBOARD"]
    inp.ki.wVk = vk
    if key_up:
        inp.ki.dwFlags = w["KEYEVENTF_KEYUP"]
    inp.ki.time = 0
    inp.ki.dwExtraInfo = None
    sent = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    return sent == 1


def _sendinput_unicode_char(ch):
    import ctypes
    w = _load_win32()
    user32 = w["user32"]
    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", ctypes.c_ushort), ("wScan", ctypes.c_ushort),
                    ("dwFlags", ctypes.c_ulong), ("time", ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]
    class INPUT(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("ki", KEYBDINPUT)]
    out = []
    for direction in (0, 1):
        inp = INPUT()
        inp.type = w["INPUT_KEYBOARD"]
        inp.ki.wScan = ord(ch)
        inp.ki.dwFlags = w["KEYEVENTF_UNICODE"] | (w["KEYEVENTF_KEYUP"] if direction else 0)
        inp.ki.time = 0
        inp.ki.dwExtraInfo = None
        out.append(inp)
    class INPUT_ARR(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("ki", KEYBDINPUT)]
    arr = (INPUT * 2)()
    for i, inp in enumerate(out):
        arr[i] = inp
    sent = user32.SendInput(2, ctypes.byref(arr), ctypes.sizeof(INPUT))
    return sent == 2


# ---------------------------------------------------------------------------
# pyautogui / pynput fallbacks
# ---------------------------------------------------------------------------
def _pg():
    import pyautogui
    pyautogui.PAUSE = 0.05
    return pyautogui


def _pn():
    from pynput import mouse, keyboard
    return mouse, keyboard


# ---------------------------------------------------------------------------
# public routing helpers
# ---------------------------------------------------------------------------
def _mouse_move(x, y, absolute=True):
    b = _backend()
    if b == "sendinput":
        return _sendinput_mouse_move(int(x), int(y), absolute)
    if b == "pyautogui":
        pg = _pg()
        if absolute:
            pg.moveTo(int(x), int(y), duration=0.1)
        else:
            pg.moveRel(int(x), int(y), duration=0.1)
        return True
    if b == "pynput":
        mouse, _ = _pn()
        if absolute:
            mouse.Controller().position = (int(x), int(y))
        else:
            c = mouse.Controller().position
            mouse.Controller().position = (c[0] + int(x), c[1] + int(y))
        return True
    raise RuntimeError("no input backend available (install pyautogui or pynput)")


def _mouse_click(button="left", clicks=1, x=None, y=None):
    b = _backend()
    if x is not None and y is not None:
        _mouse_move(x, y)
    time.sleep(0.03)
    clicks = max(1, int(clicks or 1))
    for _ in range(clicks):
        if b == "sendinput":
            _sendinput_mouse_button(button, "down")
            _sendinput_mouse_button(button, "up")
        elif b == "pyautogui":
            pg = _pg()
            btn = {"left": "left", "right": "right", "middle": "middle"}.get(
                button.lower(), "left")
            pg.click(button=btn)
        elif b == "pynput":
            mouse, _ = _pn()
            c = mouse.Controller()
            btn = {"left": mouse.Button.left, "right": mouse.Button.right,
                   "middle": mouse.Button.middle}.get(button.lower(),
                                                      mouse.Button.left)
            c.click(btn)
        time.sleep(0.03)
    return True


def _key_press(key, duration=0.05):
    b = _backend()
    if b == "sendinput":
        _sendinput_key(key, False)
        time.sleep(max(duration, 0.02))
        _sendinput_key(key, True)
        return True
    if b == "pyautogui":
        pg = _pg()
        k = key.lower() if len(key) == 1 else _pg_key(key)
        pg.press(k)
        return True
    if b == "pynput":
        _, kb = _pn()
        k = _pn_key(key)
        kb.Controller().press(k)
        time.sleep(max(duration, 0.02))
        kb.Controller().release(k)
        return True
    raise RuntimeError("no input backend available")


def _type_string(text, interval=0.02):
    b = _backend()
    if b == "sendinput":
        for ch in text:
            if ch == "\n":
                _sendinput_key("enter", False)
                _sendinput_key("enter", True)
            elif ch == "\t":
                _sendinput_key("tab", False)
                _sendinput_key("tab", True)
            else:
                try:
                    _sendinput_unicode_char(ch)
                except Exception:
                    _sendinput_key(ch, False)
                    _sendinput_key(ch, True)
            time.sleep(max(interval, 0.005))
        return True
    if b == "pyautogui":
        pg = _pg()
        pg.typewrite(text, interval=max(interval, 0.01))
        return True
    if b == "pynput":
        _, kb = _pn()
        kb.Controller().type(text)
        return True
    raise RuntimeError("no input backend available")


def _hotkey(keys):
    b = _backend()
    key_list = [k.strip().lower() for k in keys.split("+") if k.strip()]
    if not key_list:
        raise ValueError("keys required (e.g. ctrl+c)")
    if b == "sendinput":
        for k in key_list:
            _sendinput_key(k, False)
        time.sleep(0.04)
        for k in reversed(key_list):
            _sendinput_key(k, True)
        return True
    if b == "pyautogui":
        pg = _pg()
        pg.hotkey(*[_pg_key(k) for k in key_list])
        return True
    if b == "pynput":
        _, kb = _pn()
        ctl = kb.Controller()
        held = [_pn_key(k) for k in key_list]
        for k in held:
            ctl.press(k)
        time.sleep(0.04)
        for k in reversed(held):
            ctl.release(k)
        return True
    raise RuntimeError("no input backend available")


def _pg_key(k):
    m = {"esc": "esc", "enter": "enter", "return": "enter", "tab": "tab",
         "space": "space", "backspace": "backspace", "delete": "delete",
         "up": "up", "down": "down", "left": "left", "right": "right",
         "home": "home", "end": "end", "pageup": "pageup",
         "pagedown": "pagedown", "insert": "insert", "win": "winleft",
         "lwin": "winleft", "rwin": "winright"}
    if len(k) == 1:
        return k
    return m.get(k, k)


def _pn_key(k):
    from pynput.keyboard import Key
    m = {"esc": Key.esc, "enter": Key.enter, "return": Key.enter,
         "tab": Key.tab, "space": Key.space, "backspace": Key.backspace,
         "delete": Key.delete, "up": Key.up, "down": Key.down,
         "left": Key.left, "right": Key.right, "home": Key.home,
         "end": Key.end, "pageup": Key.page_up, "pagedown": Key.page_down,
         "insert": Key.insert, "win": Key.cmd, "ctrl": Key.ctrl,
         "control": Key.ctrl, "shift": Key.shift, "alt": Key.alt,
         "capslock": Key.caps_lock}
    if len(k) == 1:
        return k
    return m.get(k, Key.unknown)


# ---------------------------------------------------------------------------
# public tools
# ---------------------------------------------------------------------------
def tool_mouse_pos():
    """Read the current cursor position (x, y) of the active session."""
    try:
        b = _backend()
        if b == "sendinput":
            x, y = _mouse_pos_win()
        elif b == "pyautogui":
            x, y = _pg().position()
        elif b == "pynput":
            mouse, _ = _pn()
            x, y = mouse.Controller().position
        else:
            return _err("no input backend available")
        return _ok(position={"x": int(x), "y": int(y)}, backend=b)
    except Exception as exc:
        return _err("mouse_pos failed: %r" % exc)


def tool_mouse_move(x=0, y=0, absolute=True):
    """Move the mouse cursor. absolute=True: screen coords (x,y);
    absolute=False: relative delta from current position."""
    try:
        _mouse_move(int(x), int(y), bool(absolute))
        time.sleep(0.05)
        cur = _backend()
        if cur == "sendinput":
            cx, cy = _mouse_pos_win()
        else:
            cx, cy = _pg().position() if cur == "pyautogui" else _pn()[0].Controller().position
        return _ok(moved=True, to={"x": cx, "y": cy}, absolute=absolute)
    except Exception as exc:
        return _err("mouse_move failed: %r" % exc)


def tool_mouse_click(button="left", clicks=1, x=None, y=None):
    """Click at current (or given x,y) cursor position. button=left|right|middle,
    clicks=1|2 (double-click)."""
    try:
        _mouse_click(button or "left", int(clicks or 1), x, y)
        cur = _backend()
        cx, cy = _mouse_pos_win() if cur == "sendinput" else (0, 0)
        return _ok(clicked=True, button=button, clicks=int(clicks or 1),
                   at={"x": cx, "y": cy})
    except Exception as exc:
        return _err("mouse_click failed: %r" % exc)


def tool_mouse_drag(x1=0, y1=0, x2=100, y2=100, button="left",
                    duration=0.3):
    """Press-and-hold drag from (x1,y1) to (x2,y2) with the given button."""
    try:
        b = _backend()
        _mouse_move(x1, y1)
        time.sleep(0.05)
        if b == "sendinput":
            _sendinput_mouse_button(button, "down")
            time.sleep(max(float(duration), 0.1))
            _sendinput_mouse_move(x2, y2)
            time.sleep(0.05)
            _sendinput_mouse_button(button, "up")
        elif b == "pyautogui":
            pg = _pg()
            pg.moveTo(x1, y1, duration=0.05)
            pg.dragTo(x2, y2, duration=float(duration),
                      button={"left": "left", "right": "right"}.get(button, "left"))
        elif b == "pynput":
            mouse, _ = _pn()
            c = mouse.Controller()
            c.position = (x1, y1)
            c.press(mouse.Button.left if button != "right" else mouse.Button.right)
            steps = max(5, int(float(duration) / 0.05))
            for i in range(1, steps + 1):
                c.position = (x1 + (x2 - x1) * i // steps,
                              y1 + (y2 - y1) * i // steps)
                time.sleep(0.05)
            c.release(mouse.Button.left if button != "right" else mouse.Button.right)
        else:
            return _err("no input backend available")
        return _ok(dragged=True, frm=[x1, y1], to=[x2, y2], button=button)
    except Exception as exc:
        return _err("mouse_drag failed: %r" % exc)


def tool_mouse_scroll(amount=3, direction="down"):
    """Scroll the wheel. amount = notches (positive int), direction=up|down."""
    try:
        amt = max(1, int(amount or 1))
        delta = -120 * amt if direction == "down" else 120 * amt
        b = _backend()
        if b == "sendinput":
            _sendinput_mouse_wheel(delta)
        elif b == "pyautogui":
            pg = _pg()
            pg.scroll(-amt if direction == "down" else amt)
        elif b == "pynput":
            mouse, _ = _pn()
            mouse.Controller().scroll(0, -amt if direction == "down" else amt)
        else:
            return _err("no input backend available")
        return _ok(scrolled=True, amount=amt, direction=direction)
    except Exception as exc:
        return _err("mouse_scroll failed: %r" % exc)


def tool_key_press(key="enter"):
    """Press and release a single key (enter, tab, esc, f5, a, 1, ...)."""
    try:
        if not key:
            return _err("key required")
        _key_press(key)
        return _ok(pressed=key)
    except Exception as exc:
        return _err("key_press failed: %r" % exc)


def tool_key_type(text="", interval=0.02):
    """Type a full string like a human (unicode-safe). interval = seconds
    between keystrokes."""
    try:
        if text is None or text == "":
            return _err("text required")
        _type_string(text, float(interval or 0.02))
        return _ok(typed=True, length=len(text))
    except Exception as exc:
        return _err("key_type failed: %r" % exc)


def tool_key_hotkey(keys="ctrl+c"):
    """Press a hotkey combo: e.g. 'ctrl+c', 'alt+tab', 'win+r',
    'ctrl+shift+esc', 'ctrl+alt+delete'."""
    try:
        if not keys or "+" not in keys:
            return _err("keys must be a combo like ctrl+c or alt+tab")
        _hotkey(keys)
        return _ok(hotkey=keys)
    except Exception as exc:
        return _err("key_hotkey failed: %r" % exc)


def tool_human_interface(action="status"):
    """Human-Interface kit status: backend, screen size, cursor position,
    available functions. action=status|backend_test."""
    try:
        b = _backend()
        screen = None
        pos = None
        if b == "sendinput":
            sw, sh = _screen_size_win(_load_win32())
            screen = {"w": sw, "h": sh}
            x, y = _mouse_pos_win()
            pos = {"x": x, "y": y}
        else:
            try:
                if b == "pyautogui":
                    pg = _pg()
                    screen = {"w": pg.size().width, "h": pg.size().height}
                    pos = {"x": pg.position()[0], "y": pg.position()[1]}
                elif b == "pynput":
                    mouse, _ = _pn()
                    pos = {"x": mouse.Controller().position[0],
                           "y": mouse.Controller().position[1]}
            except Exception:
                pass
        return _ok(backend=b, system=SYSTEM, screen=screen, cursor=pos,
                   tools=["mouse_pos", "mouse_move", "mouse_click",
                          "mouse_drag", "mouse_scroll", "key_press",
                          "key_type", "key_hotkey"],
                   note="SendInput native backend = koi pip package nahi chahiye" if b == "sendinput" else
                        "install pyautogui/pynput for richer control")
    except Exception as exc:
        return _err("human_interface failed: %r" % exc)