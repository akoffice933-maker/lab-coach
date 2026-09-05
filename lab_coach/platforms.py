"""Профили площадок (§10.4, F-PLT) + VPN-guess + capabilities для doctor/MCP."""
from __future__ import annotations

import ipaddress
import shutil
import socket

from .config import Settings
from .llm import ollama_probe, resolve_endpoint
from .scanners import tool_available

PLATFORM_HINTS = {
    "thm": "TryHackMe: поднимите .ovpn комнаты, цель — IP из карточки комнаты (10.x).",
    "htb": "Hack The Box: VPN; цель — выданный 10.129/10.10.10. Public docker — только SPAWNED_TARGET.",
    "standoff365": "Standoff 365 (учения): VPN полигона; один IP из брифа, не подсеть. Bounty/прод — отказ.",
    "hackthissite": "Hack This Site: варгейм на публичном сайте — сканирование запрещено, только explain_mission.",
    "vulnhub": "VulnHub: своя VM в host-only сети.",
    "metasploitable": "Metasploitable: своя VM (например 192.168.56.0/24 host-only).",
    "custom": "Custom: задайте ALLOWED_LAB_CIDRS под свою lab-сеть.",
    "ctf": "CTF-арена (Try Out): только свой заспавненный инстанс через SPAWNED_TARGET, всё остальное deny.",
}


def _local_ips() -> list[str]:
    out: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
    except socket.gaierror:
        pass
    for fallback in ("10.255.255.1", "192.168.56.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((fallback, 9))
            ip = s.getsockname()[0]
            if ip not in out:
                out.append(ip)
            s.close()
        except OSError:
            continue
    return out


def vpn_guess() -> dict:
    """Эвристика: есть ли локальный адрес в 10/8 (tun/tap THM/HTB)."""
    ips = _local_ips()
    tun_like = False
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
            if a.version == 4 and a in ipaddress.ip_network("10.0.0.0/8"):
                tun_like = True
        except ValueError:
            continue
    return {"likely_vpn": tun_like, "local_ips_count": len(ips)}


def capabilities(s: Settings) -> dict:
    vpn = vpn_guess()
    cidrs = s.effective_cidrs
    wide_warn = False
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.num_addresses > 65536:  # шире /16
                wide_warn = True
        except ValueError:
            continue
    provider = (s.llm_provider or "openrouter").lower()
    base, key, model = resolve_endpoint(s)
    # Ключ нужен всем, кроме ollama (там достаточно живого демона).
    key_set = True if provider == "ollama" else bool(key)
    ollama: dict = {}
    if provider == "ollama":
        ollama = ollama_probe(base)
    return {
        "platform": s.lab_platform,
        "platform_hint": PLATFORM_HINTS.get(s.lab_platform, ""),
        "cidrs": cidrs,
        "cidr_too_wide_warn": wide_warn,
        "vpn_guess": vpn,
        "require_vpn": s.require_vpn,
        "nuclei_available": tool_available(s.nuclei_path or "nuclei"),
        "nmap_available": tool_available("nmap") and s.nmap_enabled,
        "nmap_enabled": s.nmap_enabled,
        "llm_enabled": s.llm_enabled,
        "llm_provider": provider,
        "llm_model": model,
        "llm_base_url": base,
        "llm_key_set": key_set,
        "ollama": ollama,
        "admin_configured": bool(s.admin_ids),
        "spawned_target_set": bool(s.spawned_target),
        "allow_loopback": s.allow_loopback,
        "max_scans_per_hour": s.max_scans_per_hour,
    }
