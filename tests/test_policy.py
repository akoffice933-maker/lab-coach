"""Тесты политики LabPolicy (приёмка L0): public deny, lab allow, mixed DNS deny, пустой CIDR."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lab_coach.config import Settings
from lab_coach.policy import check_hostname_allowed, check_ip_allowed, check_target_allowed


def lab_settings(**kw):
    base = dict(admin_ids=["1"], lab_platform="custom",
                allowed_lab_cidrs_raw="192.168.56.0/24",
                allow_loopback=False, spawned_target="")
    base.update(kw)
    return Settings(**{k: v for k, v in base.items() if k in Settings.__dataclass_fields__})


def test_public_ip_denied():
    s = lab_settings()
    for ip in ("8.8.8.8", "1.1.1.1"):
        r = check_ip_allowed(ip, s)
        assert not r.allowed, ip
        assert r.reason in ("public_denied", "not_in_lab")


def test_lab_ip_allowed():
    s = lab_settings()
    r = check_ip_allowed("192.168.56.10", s)
    assert r.allowed, r


def test_lab_ip_outside_cidr_denied():
    s = lab_settings()
    r = check_ip_allowed("192.168.1.10", s)
    assert not r.allowed


def test_empty_cidr_denies_all():
    s = lab_settings(allowed_lab_cidrs_raw="")
    r = check_ip_allowed("192.168.56.10", s)
    assert not r.allowed
    assert r.reason == "empty_allowlist"


def test_mixed_dns_denied(monkeypatch):
    import lab_coach.policy as P
    s = lab_settings()
    monkeypatch.setattr(P, "resolve_host", lambda h: ["192.168.56.10", "1.2.3.4"])
    r = check_hostname_allowed("evil.example", s)
    assert not r.allowed
    # user-facing текст не светит IP
    assert "192.168.56.10" not in r.user_message
    assert "1.2.3.4" not in r.user_message


def test_dns_public_only_denied(monkeypatch):
    import lab_coach.policy as P
    s = lab_settings()
    monkeypatch.setattr(P, "resolve_host", lambda h: ["1.2.3.4"])
    r = check_target_allowed("evil.example", s)
    assert not r.allowed


def test_metadata_denied():
    s = lab_settings()
    r = check_ip_allowed("169.254.169.254", s)
    assert not r.allowed
    r2 = check_target_allowed("metadata.google.internal", s)
    assert not r2.allowed


def test_loopback_denied_by_default():
    s = lab_settings()
    assert not check_ip_allowed("127.0.0.1", s).allowed


def test_loopback_allowed_when_explicit():
    s = lab_settings(allow_loopback=True, allowed_lab_cidrs_raw="127.0.0.0/8,192.168.56.0/24")
    assert check_ip_allowed("127.0.0.1", s).allowed


def test_userinfo_and_scheme_denied():
    s = lab_settings()
    assert not check_target_allowed("http://user:pass@192.168.56.10/", s).allowed
    assert not check_target_allowed("ftp://192.168.56.10/", s).allowed
    assert not check_target_allowed("x" * 3000, s).allowed


def test_hackthissite_scan_denied():
    s = lab_settings(lab_platform="hackthissite")
    assert not check_ip_allowed("192.168.56.10", s).allowed
    assert not check_target_allowed("http://192.168.56.10/", s).allowed


def test_host_port_lab_allowed():
    s = lab_settings()
    r = check_target_allowed("192.168.56.10:8080", s)
    assert r.allowed, r


def test_ipv6_bracket_split():
    from lab_coach.policy import split_host_port
    host, port = split_host_port("[fd00::1]:8080")
    assert host == "fd00::1"
    assert port == 8080


def test_htb_spawned_target_exception():
    s = lab_settings(lab_platform="htb", spawned_target="203.0.113.10")
    r = check_ip_allowed("203.0.113.10", s)
    assert r.allowed
    r2 = check_ip_allowed("198.51.100.5", s)
    assert not r2.allowed
