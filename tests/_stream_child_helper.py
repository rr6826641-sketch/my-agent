"""Helper child process for tests/test_stream_events.py.

Prints three lines to stdout with short sleeps so subscribers can observe
output arriving while the process is still running, then one stderr line.
"""
import sys
import time

for i, line in enumerate(["alpha", "beta", "gamma"]):
    print(line, flush=True)
    time.sleep(0.25)
print("delta", file=sys.stderr, flush=True)
time.sleep(0.25)
sys.exit(0)