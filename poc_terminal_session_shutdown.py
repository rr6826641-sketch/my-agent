"""Task-scoped check: terminal interactive-session teardown at process exit.

Starts a long-running interactive session, then exits WITHOUT calling
kill_session(). The atexit hook must kill the child and join the pump/
monitor daemon threads before interpreter finalisation (no access
violation on stderr, no orphaned child process).
"""
import os
import sys

sys.path.insert(0, ".")

from ai_agent.tools import terminal as T

if os.name == "nt":
    cmd = "ping -n 120 127.0.0.1"
else:
    cmd = "sleep 120"

res = T.tool_start_session(cmd, name="poc-long")
sys.stderr.write("CHECK: start_session -> %s\n" % res.splitlines()[0])
sid = res.split("session ")[1].split(" ")[0]
sess = T._SESSIONS[sid]
sys.stderr.write("CHECK: pid=%s threads=%d\n"
                 % (sess.proc.pid, len(sess._threads)))
sys.stderr.write("CHECK: exiting WITHOUT kill_session()\n")
sys.stderr.flush()
# Deliberately no kill_session(): relies on the atexit teardown hook.
