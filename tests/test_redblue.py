"""Red vs Blue: матрица ролей, брифы, harden_checklist, verify_fix."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach import coach
from lab_coach.mcp import ROLE_TOOLS, _dispatch_tool


def _env(monkeypatch, tmp_path, role="coach"):
    monkeypatch.setenv("AGENT_ROLE", role)
    monkeypatch.setenv("HTB_DIR", str(tmp_path / "HTB"))
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("ALLOWED_LAB_CIDRS", "192.168.56.0/24")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///" + str(tmp_path / "lab.db"))


def test_matrix_shape():
    assert ROLE_TOOLS["coach"] is None
    assert "get_plan_step" in ROLE_TOOLS["red"]
    assert "harden_checklist" not in ROLE_TOOLS["red"]
    assert "verify_fix" not in ROLE_TOOLS["red"]
    assert "harden_checklist" in ROLE_TOOLS["blue"]
    assert "verify_fix" in ROLE_TOOLS["blue"]
    assert "get_plan_step" not in ROLE_TOOLS["blue"]
    assert "scan_lab_target" not in ROLE_TOOLS["blue"]
    assert "set_platform" not in ROLE_TOOLS["red"] | ROLE_TOOLS["blue"]


def test_red_denied_blue_tools(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, "red")
    r = _dispatch_tool("harden_checklist", {"title": "SQLi"})
    assert r.get("isError") and "роли" in r["content"][0]["text"]
    assert _dispatch_tool("verify_fix", {"target": "x", "baseline": "y"}).get("isError")
    assert _dispatch_tool("set_platform", {"platform": "thm"}).get("isError")


def test_blue_denied_red_tools(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, "blue")
    assert _dispatch_tool("get_plan_step", {"step": "1"}).get("isError")
    assert _dispatch_tool("scan_lab_target", {"target": "192.168.56.110"}).get("isError")
    r = _dispatch_tool("get_role_brief", {})
    assert not r.get("isError") and "BLUE" in r["content"][0]["text"]


def test_coach_allows_all(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, "coach")
    assert not _dispatch_tool("get_plan_step", {"step": "0"}).get("isError")
    assert not _dispatch_tool("harden_checklist", {"title": "XSS"}).get("isError")


def test_harden_checklist_classes():
    assert coach.harden_checklist("SQL Injection in login")["class"] == "SQL-инъекция"
    x = coach.harden_checklist("Missing CSP header")
    assert x["class"] == "HTTP-заголовки" or "CSP" in " ".join(x["checklist"])
    u = coach.harden_checklist("Something unknown here")
    assert u["class"] == "Общая находка" and len(u["checklist"]) >= 3


def test_verify_fix_denied_public(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, "blue")
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"findings": []}), encoding="utf-8")
    r = coach.verify_fix("8.8.8.8", str(base))
    assert not r["ok"]


def test_verify_fix_lab_no_scanner(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, "blue")
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"findings": [
        {"scanner": "nuclei", "severity": "high", "title": "SQL Injection",
         "description": "", "location": "http://x/", "impact": ""}]}),
        encoding="utf-8")
    r = coach.verify_fix("192.168.56.110", str(base))
    assert r["ok"], r
    assert r["reliable"] is False  # nuclei нет — сравнение условно, честно сказано
    assert "условно" in r["verdict"]
