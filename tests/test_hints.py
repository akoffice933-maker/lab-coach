"""Категории next_action и SOFT_HINTS без payload."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach import coach
from lab_coach.hints import detect_category, normalize_category, soft_hints_for


def _env(monkeypatch, tmp_path, **extra):
    monkeypatch.setenv("LAB_PLATFORM", "custom")
    monkeypatch.setenv("HTB_DIR", str(tmp_path / "HTB"))
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("ALLOWED_LAB_CIDRS", "192.168.56.0/24")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///" + str(tmp_path / "lab.db"))
    monkeypatch.delenv("SOFT_HINTS", raising=False)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_normalize_category():
    assert normalize_category("rev") == "reversing"
    assert normalize_category("WEB") == "web"
    assert normalize_category("nope") == ""


def test_detect_web_from_ports():
    ports = [{"port": 80, "proto": "tcp", "service": "http"}]
    assert detect_category(ports=ports) == "web"


def test_soft_hints_off_by_default():
    assert soft_hints_for("admin ping form", enabled=False) == []


def test_soft_hints_ping_no_payload():
    hints = soft_hints_for("Admin Utility form ping traceroute", enabled=True)
    assert hints
    blob = " ".join(hints).lower()
    assert "shell" in blob or "команд" in blob
    assert ";" not in blob
    assert "payload" not in blob
    assert "`" not in blob


def test_next_action_category_web(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    assert coach.init_session("box", "192.168.56.110", category="web")["ok"]
    nxt = coach.next_action("box", category="web")
    assert nxt["ok"]
    assert nxt["category"] == "web"
    assert any("форм" in x.lower() or "ввод" in x.lower() for x in nxt["you_run"] + nxt["questions"])
    assert nxt["soft_hints_enabled"] is False


def test_next_action_soft_hints_from_ingest(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, SOFT_HINTS="true")
    assert coach.init_session("box", "192.168.56.110", category="web")["ok"]
    html = '<h1>Admin Utility</h1>\n<form action="/admin/ping" method="POST">'
    r = coach.ingest_output("box", "http", html)
    assert r["ok"]
    assert r.get("soft_hints")
    nxt = coach.next_action("box")
    assert nxt["soft_hints_enabled"] is True
    assert nxt["soft_hints"]
    blob = json.dumps(nxt).lower()
    assert "msfvenom" not in blob
    assert "reverse shell" not in blob
