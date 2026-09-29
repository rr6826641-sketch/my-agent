"""Windows: stop child processes from flashing console windows.

When the app runs windowed (frozen MyAgentUltra.exe or pythonw), every
subprocess spawn -- subprocess.run / Popen, shell=True or list form --
allocates a visible console window for console children (cmd.exe,
nslookup, tasklist, docker, netstat, ...). That is the "cmd flash" users
see on every agent command.

This module patches subprocess.Popen.__init__ once, on Windows only, to
inject CREATE_NO_WINDOW whenever the caller did not pass creationflags
explicitly. Callers that pass their own creationflags (ConPTY/pty
helpers, DETACHED_PROCESS daemons, ...) are left untouched.

Idempotent; no-op on non-Windows. Call apply() early, before any
subprocess is spawned (ai_agent/__init__.py does this at import time).
"""

import os
import subprocess

_APPLIED = False


def apply():
    """Install the CREATE_NO_WINDOW default for this process (once)."""
    global _APPLIED
    if _APPLIED or os.name != "nt":
        return
    _APPLIED = True
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    orig_init = subprocess.Popen.__init__

    def _popen_init(self, *args, **kwargs):
        if kwargs.get("creationflags") is None:
            kwargs["creationflags"] = flags
        return orig_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _popen_init
