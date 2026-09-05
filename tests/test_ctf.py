"""CTF-режим: профиль ctf, SPAWNED_TARGET host:port, плейбуки, матрица ролей."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach import coach
from lab_coach.config import PLATFORM_CIDRS, VALID_PLATFORMS, Settings, load_settings


def test_ctf_profile_registered(monkeypatch):
    # Страж: профиль должен резолвиться из env, а не откатываться в custom
    monkeypatch.setenv("LAB_PLATFORM", "ctf")
    assert "ctf" in VALID_PLATFORMS
    assert "ctf" in PLATFORM_CIDRS
    assert load_settings().lab_platform == "ctf"
    assert load_settings().effective_cidrs == []
from lab_coach.mcp import ROLE_TOOLS, _dispatch_tool
from lab_coach.policy import check_target_allowed, normalize_scan_target


def ctf_settings(**kw):
    base = dict(admin_ids=["1"], lab_platform="ctf",
                allowed_lab_cidrs_raw="10.10.10.0/23,10.129.0.0/16",
                allow_loopback=False, spawned_target="203.0.113.50")
    base.update(kw)
    return Settings(**{k: v for k, v in base.items() if k in Settings.__dataclass_fields__})


def test_spawned_instance_allowed_with_port():
    s = ctf_settings()
    r = check_target_allowed("203.0.113.50:8080", s)
    assert r.allowed, (r.reason, r.log_detail)
    assert "port=8080" in r.log_detail


def test_spawned_with_port_in_env():
    # Регрессия: SPAWNED_TARGET вида IP:port (как в .env.ctf) тоже работает
    s = ctf_settings(spawned_target="203.0.113.50:8080")
    assert check_target_allowed("203.0.113.50:8080", s).allowed
    assert check_target_allowed("203.0.113.50", s).allowed
    assert not check_target_allowed("198.51.100.9:8080", s).allowed


def test_other_public_denied_even_in_ctf():
    s = ctf_settings()
    assert not check_target_allowed("198.51.100.9:8080", s).allowed
    assert not check_target_allowed("8.8.8.8", s).allowed


def test_lab_ip_denied_in_ctf_without_spawn():
    # Профиль ctf: CIDR пуст → разрешён ТОЛЬКО заспавненный инстанс
    s = ctf_settings()
    assert not check_target_allowed("10.129.5.5", s).allowed


def test_empty_spawned_denies_all():
    s = ctf_settings(spawned_target="")
    assert not check_target_allowed("203.0.113.50:8080", s).allowed


def test_bad_port_denied():
    s = ctf_settings()
    assert not check_target_allowed("203.0.113.50:99999", s).allowed
    assert not check_target_allowed("203.0.113.50:0", s).allowed


def test_normalize_scan_target():
    assert normalize_scan_target("203.0.113.50:8080") == "http://203.0.113.50:8080"
    assert normalize_scan_target("192.168.56.10") == "192.168.56.10"
    assert normalize_scan_target("http://x/y") == "http://x/y"


def test_playbooks():
    w = coach.get_ctf_playbook("web")
    assert w["ok"] and "SPAWNED_TARGET" in w["playbook"] and "loot" in w["rules"]
    assert coach.get_ctf_playbook("rev")["category"] == "Reversing"
    g = coach.get_ctf_playbook("quantum")
    assert g["ok"] and g["category"] == "Generic" and len(g["known"]) >= 8


def test_matrix_ctf_tool_both_roles(monkeypatch, tmp_path):
    monkeypatch.setenv("HTB_DIR", str(tmp_path / "HTB"))
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///" + str(tmp_path / "lab.db"))
    assert "get_ctf_playbook" in ROLE_TOOLS["red"]
    assert "get_ctf_playbook" in ROLE_TOOLS["blue"]
    for role in ("red", "blue", "coach"):
        monkeypatch.setenv("AGENT_ROLE", role)
        r = _dispatch_tool("get_ctf_playbook", {"category": "forensics"})
        assert not r.get("isError"), (role, r)
