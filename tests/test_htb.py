"""Профиль HTB: CIDR машин, fail-closed VPN, dotenv, SPAWNED_TARGET без VPN."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach.config import Settings, load_dotenv, load_settings
from lab_coach.platforms import vpn_required_ok
from lab_coach.policy import check_ip_allowed, check_target_allowed


def htb(**kw):
    base = dict(admin_ids=["1"], lab_platform="htb", require_vpn=True,
                allowed_lab_cidrs_raw="10.10.10.0/23,10.129.0.0/16",
                allow_loopback=False, spawned_target="")
    base.update(kw)
    return Settings(**{k: v for k, v in base.items() if k in Settings.__dataclass_fields__})


def test_htb_machine_ip_allowed():
    s = htb()
    assert check_ip_allowed("10.129.22.153", s).allowed
    assert check_ip_allowed("10.10.10.10", s).allowed
    assert check_ip_allowed("10.10.11.5", s).allowed


def test_htb_denies_public_and_lan_and_tun():
    s = htb()
    assert not check_ip_allowed("8.8.8.8", s).allowed
    assert not check_ip_allowed("192.168.56.10", s).allowed
    # tun0 клиента — не цель карточки машины
    assert not check_ip_allowed("10.10.14.2", s).allowed


def test_vpn_fail_closed(monkeypatch):
    import lab_coach.platforms as P
    monkeypatch.setattr(P, "vpn_guess", lambda: {"likely_vpn": False})
    s = htb()
    ok, msg = vpn_required_ok(s, "10.129.1.1")
    assert not ok and "VPN" in msg


def test_vpn_ok_when_tun(monkeypatch):
    import lab_coach.platforms as P
    monkeypatch.setattr(P, "vpn_guess", lambda: {"likely_vpn": True})
    s = htb()
    assert vpn_required_ok(s, "10.129.1.1")[0]


def test_spawned_challenge_skips_vpn(monkeypatch):
    import lab_coach.platforms as P
    monkeypatch.setattr(P, "vpn_guess", lambda: {"likely_vpn": False})
    s = htb(spawned_target="203.0.113.9:1337")
    assert vpn_required_ok(s, "203.0.113.9:1337")[0]
    assert not vpn_required_ok(s, "10.129.1.1")[0]
    assert check_target_allowed("203.0.113.9:1337", s).allowed


def test_load_dotenv_does_not_override(tmp_path, monkeypatch):
    envf = tmp_path / ".env"
    envf.write_text("LAB_PLATFORM=htb\nADMIN_IDS=42\n", encoding="utf-8")
    monkeypatch.setenv("LAB_PLATFORM", "custom")
    load_dotenv(str(envf))
    assert os.environ["LAB_PLATFORM"] == "custom"
    monkeypatch.delenv("ADMIN_IDS", raising=False)
    load_dotenv(str(envf))
    assert os.environ.get("ADMIN_IDS") == "42"


def test_htb_env_example_narrows(monkeypatch, tmp_path):
    monkeypatch.setenv("LAB_COACH_STATE", str(tmp_path / "no-state.json"))
    monkeypatch.setenv("LAB_PLATFORM", "htb")
    monkeypatch.setenv("ALLOWED_LAB_CIDRS", "10.0.0.0/8,10.129.0.0/16,10.10.10.0/23")
    s = load_settings()
    assert s.lab_platform == "htb"
    cidrs = s.effective_cidrs
    assert "10.129.0.0/16" in cidrs
    assert "10.0.0.0/8" not in cidrs
