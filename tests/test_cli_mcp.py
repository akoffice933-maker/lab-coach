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


def test_mcp_forbidden_tool():
    from lab_coach.mcp import _dispatch_tool
    os.environ.setdefault("ADMIN_IDS", "1")
    r = _dispatch_tool("login", {})
    assert r.get("isError")
    r2 = _dispatch_tool("run_kaligpt", {})
    assert r2.get("isError")
