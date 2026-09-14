# -*- coding: utf-8 -*-
"""Tests for Scheduled Campaigns (bundle #6): schedule_campaign / campaign_run_now / campaign_daemon."""
import json
import os
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


class TestScheduleCampaign(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sched_test_")
        os.environ["SCHED_STORE_PATH"] = os.path.join(self.tmp, "sched.json")
        from ai_agent.tools import schedule_campaign as sc
        self.sc = sc

    def tearDown(self):
        for fn in os.listdir(self.tmp):
            try:
                os.remove(os.path.join(self.tmp, fn))
            except OSError:
                pass
        os.environ.pop("SCHED_STORE_PATH", None)

    def test_add_list_remove_roundtrip(self):
        r = json.loads(self.sc.tool_schedule_campaign(
            action="add", name="nightly", target="http://127.0.0.1:9/",
            schedule="daily 03:00", chain="auto", notify=""))
        self.assertTrue(r["ok"])
        job_id = r["job"]["id"]
        self.assertEqual(json.loads(self.sc.tool_schedule_campaign(
            action="list"))["jobs"][0]["name"], "nightly")
        rm = json.loads(self.sc.tool_schedule_campaign(action="remove", job_id=job_id))
        self.assertTrue(rm["ok"])
        self.assertEqual(json.loads(self.sc.tool_schedule_campaign(
            action="list"))["jobs"], [])

    def test_schedule_parsing(self):
        for spec in ("daily 03:00", "03:00", "every 30m", "every 2h",
                     "0 3 * * *", "*/30 * * * *"):
            with self.subTest(spec=spec):
                parsed = self.sc._parse_schedule(spec)
                self.assertIn(parsed["type"], ("daily", "interval", "cron"))
        with self.assertRaises(ValueError):
            self.sc._parse_schedule("every 10s")
        with self.assertRaises(ValueError):
            self.sc._parse_schedule("garbage")

    def test_run_now_adhoc_chain(self):
        r = json.loads(self.sc.tool_campaign_run_now(
            target="http://127.0.0.1:9/", chain="auto"))
        self.assertEqual(r["status"], "ok")
        tools = [s["tool"] for s in r["steps"]]
        self.assertIn("http_request", tools)
        self.assertIn("port_scan", tools)

    def test_enable_disable(self):
        j = json.loads(self.sc.tool_schedule_campaign(
            action="add", name="toggle", target="x", schedule="every 30m"))["job"]
        d = json.loads(self.sc.tool_schedule_campaign(
            action="disable", job_id=j["id"]))
        self.assertTrue(d["ok"])
        listed = json.loads(self.sc.tool_schedule_campaign(action="list"))["jobs"][0]
        self.assertFalse(listed["enabled"])
        e = json.loads(self.sc.tool_schedule_campaign(
            action="enable", name="toggle"))
        self.assertTrue(e["ok"])

    def test_daemon_status_no_crash(self):
        st = json.loads(self.sc.tool_campaign_daemon(action="status"))
        self.assertIn("running", st)
        self.assertIn("store", st)

    def test_run_due_campaigns_interval(self):
        j = json.loads(self.sc.tool_schedule_campaign(
            action="add", name="due", target="http://127.0.0.1:9/",
            schedule="every 30m"))["job"]
        # next_run already valid -> run_due with run_all executes it
        res = json.loads(self.sc.run_due_campaigns(run_all=True))
        self.assertEqual(res["count"], 1)
        self.assertEqual(
            json.loads(self.sc.tool_schedule_campaign(action="list"))["jobs"][0]["id"],
            j["id"])


if __name__ == "__main__":
    unittest.main()