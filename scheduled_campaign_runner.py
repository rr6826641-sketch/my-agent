#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scheduled Campaigns autopilot runner (bundle #6).

Usage:
    python scheduled_campaign_runner.py --interval 60      # foreground loop
    python scheduled_campaign_runner.py --once             # single pass
    python scheduled_campaign_runner.py --daemon --interval 30

campaign_daemon tool 'start' spawns this detached (writes PID + log via
schedule_campaign module helpers). For OS-level scheduling add this to
Windows Task Scheduler (schtasks /sc daily /st 03:00) - '--once' mode
runs the poll/tick and exits, so the task itself acts as the cron.
"""
import argparse
import json
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main():
    ap = argparse.ArgumentParser(description="Scheduled campaign autopilot")
    ap.add_argument("--interval", type=float, default=60.0,
                    help="poll seconds (default 60)")
    ap.add_argument("--once", action="store_true",
                    help="run single poll pass and exit (Task Scheduler mode)")
    ap.add_argument("--daemon", action="store_true",
                    help="loop forever (spawned detached by campaign_daemon)")
    ap.add_argument("--run-all", action="store_true",
                    help="force-run all enabled jobs on this pass")
    args = ap.parse_args()

    from ai_agent.tools.schedule_campaign import run_due_campaigns

    interval = max(30.0, float(args.interval))
    try:
        while True:
            try:
                res = run_due_campaigns(run_all=args.run_all)
                parsed = json.loads(res)
                if parsed.get("count"):
                    print(res, flush=True)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("runner error: %s: %s" % (type(e).__name__, e),
                      file=sys.stderr, flush=True)
            if args.once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
