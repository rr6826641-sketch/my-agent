"""Feature F1: Self-Upgrade tools (check_update / apply_update).

The agent can check and pull the latest version of itself from its own
GitHub remote. apply_update runs safety gates (compile + optional tests)
and rolls the repo back to the previous HEAD if a pulled update is broken.

These tests build real throwaway git repos under tmp_path (git must be on
PATH) so the pull / rollback mechanics are exercised against actual git,
with no network access required.
"""

import os
import subprocess

import pytest

from ai_agent.tools import self_upgrade as su


def _git(*args, cwd):
    proc = subprocess.run(["git"] + list(args), cwd=cwd,
                          capture_output=True, text=True)
    assert proc.returncode == 0, "git %s failed: %s" % (" ".join(args),
                                                        proc.stderr)
    return proc.stdout.strip()


def _make_repo(path, filename, content, msg):
    os.makedirs(path, exist_ok=True)
    _git("init", "-q", cwd=path)
    _git("config", "user.email", "test@example.com", cwd=path)
    _git("config", "user.name", "Test", cwd=path)
    _git("config", "commit.gpgsign", "false", cwd=path)
    with open(os.path.join(path, filename), "w", encoding="utf-8") as f:
        f.write(content)
    _git("add", ".", cwd=path)
    _git("commit", "-q", "-m", msg, cwd=path)
    return path


@pytest.fixture()
def git_env(tmp_path):
    """Bare 'origin' remote + a local clone that plays the agent repo."""
    remote = tmp_path / "origin.git"
    _git("init", "--bare", "-q", str(remote), cwd=str(tmp_path))
    local = _make_repo(str(tmp_path / "local"), "VERSION.txt", "v1\n",
                       "v1 base")
    _git("remote", "add", "origin", str(remote), cwd=local)
    _git("config", "branch.master.remote", "origin", cwd=local)
    _git("config", "branch.master.merge", "refs/heads/master", cwd=local)
    _git("push", "-q", "-u", "origin", "master", cwd=local)
    # separate working clone used to publish new upstream commits
    dev = tmp_path / "dev"
    _git("clone", "-q", str(remote), str(dev), cwd=str(tmp_path))
    _git("config", "user.email", "test@example.com", cwd=str(dev))
    _git("config", "user.name", "Test", cwd=str(dev))
    return {"remote": str(remote), "local": local, "dev": str(dev),
            "tmp": str(tmp_path)}


def _publish(git_env, filename, content, msg):
    dev = git_env["dev"]
    with open(os.path.join(dev, filename), "w", encoding="utf-8") as f:
        f.write(content)
    _git("add", ".", cwd=dev)
    _git("commit", "-q", "-m", msg, cwd=dev)
    _git("push", "-q", "origin", "master", cwd=dev)


def test_registry_exposes_self_upgrade_tools():
    from ai_agent.tools import create_tools
    tools = {t.name: t for t in create_tools(None)}
    assert "check_update" in tools
    assert "apply_update" in tools
    desc = tools["apply_update"].description.lower()
    assert "roll" in desc and "pull" in desc


def test_check_update_reports_available_update(git_env):
    _publish(git_env, "VERSION.txt", "v2\n", "v2 improvement")
    out = su.tool_check_update(repo_dir=git_env["local"])
    assert "1 commit(s) BEHIND origin" in out
    assert "master" in out
    assert "update is available" in out


def test_apply_update_pulls_and_writes_marker(git_env):
    _publish(git_env, "VERSION.txt", "v2\n", "v2 improvement")
    prev = _git("rev-parse", "HEAD", cwd=git_env["local"])
    out = su.tool_apply_update(run_tests="none", repo_dir=git_env["local"])
    assert "OK: updated" in out
    with open(os.path.join(git_env["local"], "VERSION.txt"),
              encoding="utf-8") as f:
        assert f.read().strip() == "v2"
    head = _git("rev-parse", "HEAD", cwd=git_env["local"])
    assert head != prev
    assert os.path.isfile(os.path.join(git_env["local"],
                                       su.RESTART_MARKER))
    # second run: nothing to pull
    out2 = su.tool_apply_update(run_tests="none", repo_dir=git_env["local"])
    assert "Already up to date" in out2


def test_apply_update_refuses_dirty_tree(git_env):
    _publish(git_env, "VERSION.txt", "v2\n", "v2 improvement")
    local = git_env["local"]
    with open(os.path.join(local, "VERSION.txt"), "a", encoding="utf-8") as f:
        f.write("local edit\n")
    out = su.tool_apply_update(run_tests="none", repo_dir=local)
    assert "NOT clean" in out and "force=true" in out
    # force accepts the dirty tree and still pulls
    out2 = su.tool_apply_update(run_tests="none", force=True, repo_dir=local)
    assert "OK: updated" in out2


def test_broken_update_rolls_back(git_env):
    # simulate a bad upstream change that must not survive the compile gate
    dev = git_env["dev"]
    os.makedirs(os.path.join(dev, "ai_agent"), exist_ok=True)
    with open(os.path.join(dev, "ai_agent", "badmod.py"), "w",
              encoding="utf-8") as f:
        f.write("def broken(:\n    pass\n")
    _git("add", ".", cwd=dev)
    _git("commit", "-q", "-m", "v2 broken module", cwd=dev)
    _git("push", "-q", "origin", "master", cwd=dev)

    local = git_env["local"]
    prev = _git("rev-parse", "HEAD", cwd=local)
    out = su.tool_apply_update(run_tests="none", repo_dir=local)
    assert "FAILED the compile check" in out and "rolled back" in out
    head = _git("rev-parse", "HEAD", cwd=local)
    assert head == prev
    assert not os.path.isfile(os.path.join(local, "ai_agent", "badmod.py"))


def test_not_a_repo(tmp_path):
    out = su.tool_check_update(repo_dir=str(tmp_path))
    assert "not a git repository" in out
