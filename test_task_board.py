"""Unit tests for the Built-In Task Board & State Tracking Engine.

Covers: todo -> in_progress -> completed lifecycle, the strict
one-in_progress-at-a-time constraint (preemption), the stale reaper
(hung-task recovery), close_all (turn-end auto-close), silent
machine-readable task_board events, and end-to-end Agent loop
integration (board updates must never leak into user-facing text).

Run:  py test_task_board.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ai_agent.core as core

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


class MockLLM:
    def __init__(self):
        self.model = "mock"
        self._calls = 0

    def complete(self, *a, **k):
        return "mock"

    def chat_stream(self, prompt, tools=None, cancel_event=None, model=None):
        self._calls += 1
        if self._calls == 1:
            yield {"type": "message",
                   "message": {"content": "running a scan...",
                               "tool_calls": [{
                                   "id": "call_1",
                                   "function": {
                                       "name": "port_scan",
                                       "arguments": "{\"target\": \"example.com\", \"ports\": \"80\"}",
                                   }}]}}
        else:
            yield {"type": "message",
                   "message": {"content": "All done.", "tool_calls": []}}


def run_tests():
    # ---- state constants ----------------------------------------------
    check("states_defined",
          core.TASK_STATES == (core.TASK_TODO, core.TASK_IN_PROGRESS,
                               core.TASK_COMPLETED))
    check("states_valid",
          set(core.TASK_STATES) == {"todo", "in_progress", "completed"})

    # ---- lifecycle: add -> start -> complete --------------------------
    b = core.TaskBoard()
    t1 = b.add("recon example.com")
    check("add_returns_id", t1.startswith("t"), t1)
    check("add_is_todo", b._tasks[t1]["status"] == core.TASK_TODO)
    check("counts_initial", b.counts() == {"todo": 1, "in_progress": 0,
                                           "completed": 0})
    pre = b.start(t1)
    check("start_preempts_none", pre == [])
    check("start_in_progress", b._tasks[t1]["status"] == core.TASK_IN_PROGRESS)
    check("invariant_after_start", b.check_invariants())
    check("completed_marks_done", b.complete(t1) is True)
    check("completed_state", b._tasks[t1]["status"] == core.TASK_COMPLETED)
    check("complete_idempotent", b.complete(t1) is False)
    check("completed_at_set", b._tasks[t1]["completed_at"] is not None)

    # ---- strict single-in_progress constraint -------------------------
    b2 = core.TaskBoard()
    a = b2.add("task A")
    c_ = b2.add("task C")
    b2.start(a)
    check("one_in_progress", b2.in_progress() == [a])
    pre = b2.start(c_)
    check("start_preempts_other", pre == [a], str(pre))
    check("only_one_in_progress", len(b2.in_progress()) == 1)
    check("new_task_in_progress", b2.in_progress() == [c_])
    check("preempted_back_to_todo", b2._tasks[a]["status"] == core.TASK_TODO)
    check("preempted_flag", b2._tasks[a]["preempted"] is True)
    check("invariant_strict", b2.check_invariants())
    # hammer: interleave 50 starts, constraint must never break
    ids = [b2.add("stress %d" % i) for i in range(50)]
    for i, tid in enumerate(ids):
        b2.start(tid)
        check("stress_invariant_%d" % i, b2.check_invariants(),
              "active=%s" % b2.in_progress())

    # ---- requeue (stale recovery) --------------------------------------
    b3 = core.TaskBoard()
    x = b3.add("slow step")
    b3.start(x)
    check("requeue_ok", b3.requeue(x, reason="stale") is True)
    check("requeue_todo", b3._tasks[x]["status"] == core.TASK_TODO)
    check("requeue_stale_flag", b3._tasks[x]["stale"] is True)
    check("requeue_noop_when_todo", b3.requeue(x) is False)

    # ---- stale reaper: hung in_progress task is reaped ----------------
    b4 = core.TaskBoard(stale_after=0.05)
    active = b4.add("active step")
    hung = b4.add("hung step")
    b4.start(active)
    time.sleep(0.06)
    reaped = b4.reap_stale(active_id=active)
    check("reaper_skips_active", reaped == [])
    check("active_still_in_progress",
          b4._tasks[active]["status"] == core.TASK_IN_PROGRESS)
    b4.start(hung)  # preempts active -> active back to todo
    time.sleep(0.06)
    reaped2 = b4.reap_stale(active_id=hung)
    check("reaper_skips_hung_active", reaped2 == [])
    check("hung_still_in_progress",
          b4._tasks[hung]["status"] == core.TASK_IN_PROGRESS)
    reaped3 = b4.reap_stale(active_id=None)
    check("reaper_reaps_hung", hung in reaped3, str(reaped3))
    check("reaped_back_to_todo",
          b4._tasks[hung]["status"] == core.TASK_TODO)
    check("invariant_after_reap", b4.check_invariants())

    # ---- close_all: nothing left hung/forgotten ------------------------
    b5 = core.TaskBoard()
    r = b5.add("root")
    s1 = b5.add("step1", parent=r)
    s2 = b5.add("step2", parent=r)
    b5.start(s1)
    closed = b5.close_all(reason="auto_finalized")
    check("close_all_closes_open", len(closed) == 3, str(closed))
    check("close_all_zero_in_progress", b5.counts()["in_progress"] == 0)
    check("close_all_all_completed", b5.counts()["completed"] == 3)
    check("close_all_idempotent", b5.close_all() == [])

    # ---- silent machine events -----------------------------------------
    b6 = core.TaskBoard()
    check("event_none_when_clean", b6.event() is None)
    t = b6.add("quiet task")
    ev = b6.event()
    check("event_type", ev is not None and ev["type"] == "task_board")
    check("event_machine_fields", ev is not None and "board" in ev
          and "changes" in ev)
    check("event_is_not_text", ev is not None
          and all(k.startswith("type") or k == "board" or k == "changes"
                  for k in ev.keys()))
    check("event_drains", b6.event() is None)
    b6.start(t)
    b6.complete(t)
    ev2 = b6.event()
    check("event_after_ops", ev2 is not None and len(ev2["changes"]) == 2,
          str(len(ev2["changes"]) if ev2 else None))

    # ---- snapshot shape -------------------------------------------------
    snap = b5.snapshot()
    check("snapshot_counts", snap["counts"]["completed"] == 3)
    check("snapshot_in_progress_empty", snap["in_progress"] == [])
    check("snapshot_tasks_list", isinstance(snap["tasks"], list)
          and len(snap["tasks"]) == 3)

    # ---- end-to-end: Agent loop tracks silently -------------------------
    a = core.Agent(llm=MockLLM(), memory=None, name="board-e2e")
    events = list(a.run_stream("scan example.com:80"))
    board_events = [e for e in events if e.get("type") == "task_board"]
    finals = [e for e in events if e.get("type") == "final"]
    check("e2e_board_events_emitted", len(board_events) >= 3,
          str(len(board_events)))
    check("e2e_final_present", len(finals) == 1)
    if finals:
        fc = finals[0].get("content", "")
        check("e2e_silent_final", ("task_board" not in fc
                                   and "in_progress" not in fc
                                   and "TASK" not in fc.upper()),
              fc[:60])
    check("e2e_board_exists", hasattr(a, "_task_board"))
    check("e2e_all_closed",
          a._task_board.counts()["in_progress"] == 0
          and a._task_board.counts()["todo"] == 0,
          str(a._task_board.counts()))
    check("e2e_completed_two",
          a._task_board.counts()["completed"] == 2,
          str(a._task_board.counts()))
    check("e2e_invariants", a._task_board.check_invariants())
    # one task in_progress at every observed event (strict constraint)
    for e in board_events:
        check("e2e_event_constraint",
              len(e.get("board", {}).get("in_progress", [])) <= 1,
              str(e.get("board", {}).get("in_progress")))
    # second turn after reset() starts clean
    a.reset()
    check("e2e_reset_fresh",
          a._task_board.counts() == {"todo": 0, "in_progress": 0,
                                     "completed": 0})

    # ---- summary --------------------------------------------------------
    print("\n%d passed, %d failed" % (PASS, FAIL))
    return FAIL == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
