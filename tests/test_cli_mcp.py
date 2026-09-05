"""CLI doctor/auth-deny + MCP refuse_non_stdio + fail-closed ADMIN_IDS."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)


def run_cli(*argv, env_extra=None):
    env = dict(os.environ)
    env["ADMIN_IDS"] = env.get("ADMIN_IDS", "123456789")
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, "-m", "lab_coach"] + list(argv),
                          cwd=ROOT, capture_output=True, text=True, env=env, timeout=60)


def test_doctor_ok():
    p = run_cli("doctor")
    assert p.returncode == 0, p.stderr
    assert "Lab Coach" in p.stdout


def test_scan_public_denied():
    p = run_cli("scan", "8.8.8.8")
    assert p.returncode == 3
    assert "Отказ" in p.stdout or "lab" in p.stdout.lower()


def test_auth_action_cli_denied():
    p = run_cli("login", "target")
    assert p.returncode == 3
    assert "Нет такого действия" in p.stdout


def test_fail_closed_empty_admin():
    p = run_cli("scan", "192.168.56.10", env_extra={"ADMIN_IDS": ""})
    assert p.returncode == 2
    assert "ADMIN_IDS" in (p.stdout + p.stderr)


def test_mcp_refuses_non_stdio():
    from lab_coach import mcp
    os.environ["MCP_TRANSPORT"] = "http"
    try:
        with pytest.raises(SystemExit):
            mcp.refuse_non_stdio()
    finally:
        os.environ["MCP_TRANSPORT"] = "stdio"


def test_playbook_cli():
    p = run_cli("playbook", "reversing")
    assert p.returncode == 0, p.stderr
    assert "Reversing" in p.stdout or "хосте" in p.stdout.lower() or "бинарь" in p.stdout.lower()


def test_class_cli():
    p = run_cli("class", "date format command injection")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "команд" in p.stdout.lower()


def test_plan_cli_ctf():
    p = run_cli("plan", "0", "offline", env_extra={
        "LAB_PLATFORM": "ctf", "SPAWNED_TARGET": "",
        "LAB_COACH_STATE": os.path.join(os.path.dirname(__file__), "_no_runtime_state.json"),
    })
    assert p.returncode == 0, p.stderr
    assert "Ping не" in p.stdout or "ping не" in p.stdout.lower()


def test_mcp_forbidden_tool():
    from lab_coach.mcp import _dispatch_tool
    os.environ.setdefault("ADMIN_IDS", "1")
    r = _dispatch_tool("login", {})
    assert r.get("isError")
    r2 = _dispatch_tool("run_kaligpt", {})
    assert r2.get("isError")


def test_mcp_scan_fail_closed_without_admin(monkeypatch):
    from lab_coach.mcp import _dispatch_tool
    monkeypatch.setenv("ADMIN_IDS", "")
    r = _dispatch_tool("scan_lab_target", {"target": "192.168.56.10"})
    assert r.get("isError")
    assert "ADMIN_IDS" in r["content"][0]["text"]


def test_mcp_status_ok_without_admin(monkeypatch):
    from lab_coach.mcp import _dispatch_tool
    monkeypatch.setenv("ADMIN_IDS", "")
    r = _dispatch_tool("get_lab_status", {})
    assert not r.get("isError")


def test_nuclei_safe_argv(monkeypatch):
    import lab_coach.scanners as sc
    captured = {}

    def fake_run(argv, **_kw):
        captured["argv"] = argv

        class P:
            returncode = 0
            stdout = ""
            stderr = ""

        return P()

    monkeypatch.setattr(sc.shutil, "which", lambda _b: "/usr/bin/nuclei")
    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    sc.run_nuclei("http://192.168.56.10")
    assert "-ni" in captured["argv"]
    assert "-etags" in captured["argv"]
    assert "exploit,intrusive,dos" in captured["argv"]


def test_runtime_state_overrides_env(monkeypatch, tmp_path):
    from lab_coach.config import load_settings, write_runtime_state
    st = tmp_path / "runtime-state.json"
    monkeypatch.setenv("LAB_COACH_STATE", str(st))
    monkeypatch.setenv("LAB_PLATFORM", "custom")
    write_runtime_state(lab_platform="htb")
    assert load_settings().lab_platform == "htb"
