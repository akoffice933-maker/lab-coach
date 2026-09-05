"""Coach-слой MCP: сессии, шаги, заметки, чтение файлов, политика целей."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach import coach


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("HTB_DIR", str(tmp_path / "HTB"))
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("ALLOWED_LAB_CIDRS", "192.168.56.0/24")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///" + str(tmp_path / "lab.db"))


def test_init_session_ok(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    r = coach.init_session("planbox", "192.168.56.110")
    assert r["ok"], r
    for sub in ("nmap", "loot", "exploits", "www"):
        assert os.path.isdir(os.path.join(r["dir"], sub))
    assert os.path.exists(os.path.join(r["dir"], "scope.txt"))
    assert os.path.exists(os.path.join(r["dir"], "notes.md"))


def test_init_session_public_denied(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    r = coach.init_session("evil", "8.8.8.8")
    assert not r["ok"]
    assert "lab" in r["error"].lower() or "отказ" in r["error"].lower()


def test_init_session_bad_slug(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    for bad in ("../x", "/abs", "a/b", "", "x" * 65):
        assert not coach.init_session(bad, "192.168.56.110")["ok"]


def test_status_note_read_roundtrip(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    assert coach.init_session("planbox", "192.168.56.110")["ok"]
    st = coach.session_status("planbox")
    assert st["ok"] and st["next"] == "1 recon", st
    assert coach.log_note("planbox", 1, "nmap: 22, 80 open")["ok"]
    # кладём вывод nmap и проверяем стадию
    d = coach.machine_dir("planbox")
    with open(os.path.join(d, "nmap", "allports.txt"), "w") as f:
        f.write("22/tcp open ssh\n80/tcp open http\n")
    st2 = coach.session_status("planbox")
    assert st2["stages"]["1 recon"] is True
    rd = coach.read_session_file("planbox", "nmap/allports.txt")
    assert rd["ok"] and "22/tcp" in rd["content"]
    assert not coach.read_session_file("planbox", "../../etc/passwd")["ok"]
    assert not coach.read_session_file("planbox", "/abs")["ok"]
    # напоминание на auth-подобную заметку, но сохранение работает
    r = coach.log_note("planbox", 3, "попробовать войти без пароля ???")
    assert r["ok"] and "reminder" in r


def test_plan_steps(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    for n in range(7):
        r = coach.get_plan_step(n, "192.168.56.110")
        assert r["ok"] and r["step"] == n and r["title"], (n, r)
    assert "192.168.56.110" in coach.get_plan_step(1, "192.168.56.110")["guide"]
    assert not coach.get_plan_step(9)["ok"]
    # public-цель → плейсхолдер + предупреждение, но не отказ
    r = coach.get_plan_step(1, "8.8.8.8")
    assert r["ok"] and "<IP>" in r["guide"]


def test_mcp_routes_new_tools(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    from lab_coach.mcp import _dispatch_tool
    r = _dispatch_tool("init_session", {"machine": "planbox", "target": "192.168.56.110"})
    assert not r.get("isError"), r
    r2 = _dispatch_tool("session_status", {"machine": "planbox"})
    assert not r2.get("isError"), r2
    r3 = _dispatch_tool("get_plan_step", {"step": "1"})
    assert not r3.get("isError"), r3
    r4 = _dispatch_tool("init_session", {"machine": "evil", "target": "8.8.8.8"})
    assert r4.get("isError")
