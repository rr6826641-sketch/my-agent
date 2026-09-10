"""PHASE 1 - real-time tool-execution SSE event emitter tests.

Verifies the PHASE 1 contract end to end:

  * terminal command invocations emit stream events *immediately before*
    execution (a 'running' start frame) and *during* execution (live
    stdout/stderr frames observed while the child is still running) -
    not only after completion;
  * every emitted payload carries the full JSON contract: run_id,
    session_id, ts, step_type, command, stream, stdout, stderr, status,
    exit_code, duration_ms;
  * the webui /api/exec/stream SSE generator serialises both replay (late
    joiner) and live events as `event: exec` JSON frames;
  * a stream failure can never break tool execution.

Run:
      python -m pytest tests/test_stream_events.py -v
      python -m pytest tests/ --disable-warnings
"""

import json
import os
import queue
import sys
import threading
import time
import uuid

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ai_agent.core.event_stream import EventStreamHub, hub, _step_type_for  # noqa: E402
from ai_agent.tools.terminal import tool_run_terminal  # noqa: E402

_CONTRACT = {
    "run_id", "session_id", "ts", "step_type", "command",
    "stream", "stdout", "stderr", "status", "exit_code", "duration_ms",
}


def _helper_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "_stream_child_helper.py")


def _unique(prefix):
    return "%s-%s" % (prefix, uuid.uuid4().hex[:10])


def _drain_until_terminal(q, timeout=30, run_id=None):
    """Consume subscriber events until the terminal frame for run_id."""
    events = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            evt = q.get(timeout=max(0.05, deadline - time.time()))
        except queue.Empty:
            break
        events.append(evt)
        if evt.get("run_id") == run_id and evt.get("stream") is None and \
                evt.get("status") in ("completed", "failed", "cancelled"):
            break
    return events


# ---------------------------------------------------------------- helpers


def test_payload_contract_and_step_type_mapping():
    """Every emitted event carries the full JSON contract keys, and tool
    names map onto the coarse step_type taxonomy."""
    assert _step_type_for("run_terminal") == "terminal"
    assert _step_type_for("pty_start_session") == "terminal"
    assert _step_type_for("bash") == "terminal"
    assert _step_type_for("git_commit") == "git"
    assert _step_type_for("run_git") == "git"
    assert _step_type_for("subagent_spawn") == "subagent"
    assert _step_type_for("swarm_run") == "subagent"
    assert _step_type_for("read_file") == "tool"

    hub.attach_context(run_id=_unique("schema"), session_id="sess-schema")
    try:
        sub_id, q = hub.subscribe()
        try:
            hub.subagent_state(name="validation_start", detail="sanity",
                               run_id=_unique("schema-sub"),
                               session_id="sess-schema")
            evt = q.get(timeout=5)
        finally:
            hub.unsubscribe(sub_id)
    finally:
        hub.detach_context()
    assert _CONTRACT <= set(evt), "missing contract keys: %s" % (
        _CONTRACT - set(evt),)
    assert evt["step_type"] == "subagent"
    assert evt["status"] == "running"
    assert evt["detail"] == "sanity"


def test_run_lifecycle_records_active_runs():
    run_id = _unique("lifecycle")
    hub.begin_run(run_id=run_id, step_type="tool", command="echo hi")
    try:
        assert run_id in hub.active_runs()
    finally:
        hub.end_run(run_id, "completed", 0)
    assert run_id not in hub.active_runs()


# ---------------------------------------------------------------- live runner


def test_run_command_emits_start_before_and_output_during_execution():
    """The core run_command() must emit the 'running' start frame before the
    child spawns, push live stdout/stderr frames while the child is still
    executing, and finish with a single terminal frame."""
    run_id = _unique("run-cmd")
    sub_id, q = hub.subscribe()
    result = {}
    active_while_streaming = []

    def _run():
        result["ret"] = hub.run_command(
            [sys.executable, _helper_path()], timeout=30,
            run_id=run_id, session_id="sess-live", step_type="terminal")

    try:
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        events = []
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                evt = q.get(timeout=0.5)
            except queue.Empty:
                if not t.is_alive():
                    break
                continue
            events.append(evt)
            # snapshot the live run lifecycle the moment a stdout frame is
            # consumed: it must still be marked running at that point.
            if evt.get("stream") == "stdout":
                active_while_streaming.append(
                    evt.get("run_id") in hub.active_runs()
                    and evt.get("status") == "running")
            if evt.get("run_id") == run_id and evt.get("stream") is None and \
                    evt.get("status") in ("completed", "failed", "cancelled"):
                break
        t.join(15)
    finally:
        hub.unsubscribe(sub_id)

    assert not t.is_alive(), "run_command did not finish in time"
    exit_code, stdout, stderr = result["ret"]
    assert exit_code == 0, (exit_code, stderr)
    assert "alpha" in stdout and "gamma" in stdout and "delta" in stderr

    assert events, "no stream events were emitted for the command"
    start = events[0]
    assert start["status"] == "running", "start frame must precede execution"
    assert start["stream"] is None
    assert start["step_type"] == "terminal"
    assert _helper_path() in (start.get("command") or "")

    out_frames = [e for e in events if e["stream"] == "stdout"]
    err_frames = [e for e in events if e["stream"] == "stderr"]
    assert any("alpha" in (e.get("stdout") or "") for e in out_frames)
    assert any("gamma" in (e.get("stdout") or "") for e in out_frames)
    assert any("delta" in (e.get("stderr") or "") for e in err_frames)
    assert out_frames and err_frames

    term = events[-1]
    assert term["status"] == "completed" and term["exit_code"] == 0
    assert term["stream"] is None
    assert "alpha" in (term.get("stdout") or "")
    assert "delta" in (term.get("stderr") or "")
    assert term.get("duration_ms") is not None

    # ordering contract: start -> (live running output) -> terminal
    assert all(e["status"] == "running" for e in events[:-1])
    assert active_while_streaming, (
        "no stdout frame was observed while the run was still live")
    assert any(active_while_streaming), (
        "stdout frames arrived only after the run had already ended")
    # schema: every single frame carries the full contract
    for evt in events:
        assert _CONTRACT <= set(evt), "missing keys in %s" % (evt,)


def test_run_command_streams_stderr_live_on_failure():
    """A failing command still streams its stderr live *while* running and
    finishes with a failed terminal frame (exit_code != 0)."""
    run_id = _unique("run-fail")
    sub_id, q = hub.subscribe()
    try:
        exit_code, stdout, stderr = hub.run_command(
            [sys.executable, "-c", "import sys; print('oops', file=sys.stderr); raise SystemExit(3)"],
            timeout=30, run_id=run_id, session_id="sess-fail",
            step_type="terminal")
        events = _drain_until_terminal(q, timeout=30, run_id=run_id)
    finally:
        hub.unsubscribe(sub_id)
    assert exit_code == 3
    assert "oops" in stderr
    assert events[-1]["status"] == "failed"
    assert events[-1]["exit_code"] == 3
    assert any(e["stream"] == "stderr" and "oops" in (e.get("stderr") or "")
               for e in events)


# ---------------------------------------------------------------- tool path


def test_tool_run_terminal_emits_live_events_through_shared_hub():
    """The terminal tool (as invoked by base.execute_tool) emits the same
    start -> live output -> terminal contract, and all frames share one
    run identity inherited from the attached context."""
    run_id = _unique("tool-term")
    hub.attach_context(run_id=run_id, session_id="sess-tool-1")
    sub_id, q = hub.subscribe()
    try:
        cmd = '"%s" "%s"' % (sys.executable, _helper_path())
        out = tool_run_terminal(cmd, timeout=30)
        events = _drain_until_terminal(q, timeout=30, run_id=run_id)
    finally:
        hub.unsubscribe(sub_id)
        hub.detach_context()

    assert "[exit code 0]" in out
    assert "alpha" in out and "gamma" in out

    assert events, "terminal tool emitted no stream events"
    start = events[0]
    assert start["status"] == "running" and start["stream"] is None
    assert all(e["run_id"] == run_id for e in events), (
        "all frames must share the inherited run identity")
    assert all(e["step_type"] == "terminal" for e in events)
    assert all(e["status"] == "running" for e in events[:-1])
    assert any(e["stream"] == "stdout" and "alpha" in (e.get("stdout") or "")
               for e in events)
    assert any(e["stream"] == "stderr" and "delta" in (e.get("stderr") or "")
               for e in events)
    term = events[-1]
    assert term["status"] == "completed" and term["exit_code"] == 0
    assert "alpha" in (term.get("stdout") or "")
    assert "delta" in (term.get("stderr") or "")


def test_stream_failure_never_breaks_tool_execution(monkeypatch):
    """The hub is fail-safe by design: if the stream layer raises anywhere,
    tool execution must still complete and return its normal output."""
    from ai_agent.tools import terminal as terminal_mod

    def _boom(*a, **k):
        raise RuntimeError("stream down")

    monkeypatch(terminal_mod.hub, "emit", _boom)
    out = terminal_mod.tool_run_terminal(
        '"%s" -c "print(123)"' % sys.executable, timeout=30)
    assert "[exit code 0]" in out
    assert "123" in out


# ---------------------------------------------------------------- webui SSE


def _parse_sse_frame(frame):
    parsed = {}
    for ln in frame.splitlines():
        if ln.startswith("event:"):
            parsed["event"] = ln[len("event:"):].strip()
        elif ln.startswith("data:"):
            parsed["data"] = ln[len("data:"):].strip()
    return parsed


def _next_exec_frame(gen, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        frame = next(gen)
        parsed = _parse_sse_frame(frame)
        if parsed.get("event") == "exec":
            return json.loads(parsed["data"])
    raise AssertionError("no exec frame received within %ss" % timeout)


def test_webui_exec_stream_generator_replay_and_live_push():
    """The /api/exec/stream SSE generator must replay recent history for
    late joiners AND push live frames the moment events are emitted."""
    import webui as webui_mod

    hist_run = _unique("hist-run")
    hub.subagent_state(name="validation_start", detail="sanity",
                       run_id=hist_run, session_id="sess-sse")
    # replay: a generator filtered to the historical run must deliver the
    # historical event from the replay window (late-joiner contract)
    gen = webui_mod._exec_stream_generator(after=5, run_filter=hist_run,
                                           sid_filter=None)
    try:
        first = next(gen)  # subscribe + retry line
        assert "retry: 1500" in first

        replayed = _next_exec_frame(gen)
        assert replayed["run_id"] == hist_run
        assert replayed["step_type"] == "subagent"
        assert replayed["command"] == "validation_start"
        assert replayed["detail"] == "sanity"
    finally:
        gen.close()  # generator finally -> hub.unsubscribe

    # live push: an UNFILTERED generator must push events the moment they
    # are emitted, after its subscription is established
    gen = webui_mod._exec_stream_generator(after=0)
    try:
        first = next(gen)
        assert "retry: 1500" in first
        live_run = _unique("live-run")
        hub.subagent_state(name="validation_done", status="completed",
                           detail="reported",
                           run_id=live_run, session_id="sess-sse")
        live = _next_exec_frame(gen)
        assert live["run_id"] == live_run
        assert live["command"] == "validation_done"
        assert live["status"] == "completed"
    finally:
        gen.close()