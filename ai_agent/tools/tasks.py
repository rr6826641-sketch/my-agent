"""Task / todo management for the agent (persistent JSON file).

Mirrors the todo_write capability: plan multi-step security assessments,
track one task in progress at a time, update statuses as work completes.
"""

import datetime
import json
import os
import threading

TASKS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "tasks.json",
)

_lock = threading.Lock()


def _load():
    try:
        with open(TASKS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    if not isinstance(data, dict) or "tasks" not in data:
        data = {"tasks": {}}
    return data


def _save(data):
    try:
        os.makedirs(os.path.dirname(TASKS_PATH) or ".", exist_ok=True)
        with open(TASKS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        return "save failed: %s" % exc
    return ""


def tool_manage_tasks(action="list", task_id="", content="", status=""):
    """Manage the agent's task list. actions: add, list, update, delete, clear.

    - add:      content required; optional task_id (short, e.g. 'recon'). Returns the id.
    - list:     show all tasks and their status (no other args needed).
    - update:   task_id required; set content and/or status
                (pending | in_progress | completed | cancelled).
    - delete:   task_id required.
    - clear:    remove all tasks.
    """
    action = (action or "list").strip().lower()
    task_id = (task_id or "").strip()
    content = (content or "").strip()
    status = (status or "").strip().lower()
    valid_status = {"pending", "in_progress", "completed", "cancelled"}

    with _lock:
        data = _load()

        if action == "clear":
            data["tasks"] = {}
            err = _save(data)
            return err or "all tasks cleared"

        if action == "add":
            if not content:
                return "Error: content is required for add."
            if not task_id:
                task_id = "task_%d" % (len(data["tasks"]) + 1)
            data["tasks"][task_id] = {
                "content": content,
                "status": status if status in valid_status else "pending",
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            }
            err = _save(data)
            return err or "task added: %s" % task_id

        if action == "update":
            if not task_id or task_id not in data["tasks"]:
                return "Error: task '%s' not found." % task_id
            entry = data["tasks"][task_id]
            if content:
                entry["content"] = content
            if status:
                if status not in valid_status:
                    return "Error: status must be one of %s" % sorted(valid_status)
                entry["status"] = status
            entry["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
            err = _save(data)
            return err or "task updated: %s -> %s" % (task_id, entry["status"])

        if action == "delete":
            if task_id and task_id in data["tasks"]:
                del data["tasks"][task_id]
                err = _save(data)
                return err or "task deleted: %s" % task_id
            return "Error: task '%s' not found." % task_id

        # default: list
        if not data["tasks"]:
            return "(no tasks - use manage_tasks action=add content=... to plan work)"
        lines = ["Tasks:"]
        for tid in sorted(data["tasks"]):
            entry = data["tasks"][tid]
            lines.append("- [%s] %s: %s" % (entry.get("status", "?"), tid,
                                            entry.get("content", "")))
        return "\n".join(lines)
