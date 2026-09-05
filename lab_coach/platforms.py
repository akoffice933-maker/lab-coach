"""Профили площадок (§10.4, F-PLT) + VPN-guess + capabilities для doctor/MCP."""
from __future__ import annotations

import ipaddress
import os
import socket
import struct

try:
    import fcntl  # Linux/Unix: ioctl для tun-интерфейсов (Kali/HTB)
except ImportError:  # Windows: VPN-guess работает через _local_ips fallback
    fcntl = None  # type: ignore[assignment]

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


def _iface_ipv4(name: str) -> str | None:
    """SIOCGIFADDR — адрес tun0 на Kali/Linux. На Windows — None."""
    if fcntl is None:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack("256s", name.encode("ascii", "ignore")[:15])
        ip = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24])
        sock.close()
        return ip
    except OSError:
        return None


def _tun_ips() -> list[str]:
    out: list[str] = []
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        names = []
    for name in names:
        if not name.startswith(("tun", "tap", "wg")):
            continue
        ip = _iface_ipv4(name)
        if ip and ip not in out:
            out.append(ip)
    return out


def _local_ips() -> list[str]:
    out: list[str] = list(_tun_ips())
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
    """Эвристика: tun/tap/wg с 10/8 (HTB tun0 обычно 10.10.14.x)."""
    ips = _local_ips()
    tun_ips = _tun_ips()
    net10 = ipaddress.ip_network("10.0.0.0/8")
    tun_like = False
    for ip in tun_ips or ips:
        try:
            a = ipaddress.ip_address(ip)
            if a.version == 4 and a in net10:
                tun_like = True
                break
        except ValueError:
            continue
    return {"likely_vpn": tun_like, "local_ips_count": len(ips), "tun_ips_count": len(tun_ips)}


VPN_PLATFORMS = ("thm", "htb")
VPN_REFUSAL_RU = (
    "Отказ: REQUIRE_VPN=true, а tun/tap с адресом 10/8 не найден. "
    "Подключите .ovpn площадки (sudo openvpn …) и повторите. "
    "Для публичного docker-челленджа задайте SPAWNED_TARGET."
)


def vpn_required_ok(s: Settings, target: str = "") -> tuple[bool, str]:
    """Fail-closed для thm/htb, кроме цели = SPAWNED_TARGET (challenge без VPN)."""
    if s.lab_platform not in VPN_PLATFORMS or not s.require_vpn:
        return True, ""
    spawned = (s.spawned_target or "").strip().lower()
    t = (target or "").strip().lower()
    if spawned and t:
        from .policy import split_host_port
        if split_host_port(t)[0] == split_host_port(spawned)[0]:
            return True, ""
    if vpn_guess().get("likely_vpn"):
        return True, ""
    return False, VPN_REFUSAL_RU


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
        "vpn_required_ok": vpn_required_ok(s)[0],
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
