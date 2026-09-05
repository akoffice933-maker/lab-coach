"""LabPolicy — invert относительно scan-bot: только lab, всё остальное deny.

F-POL-01..07, §10.2–10.4, F-PLT-01..07.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .config import METADATA_HOSTNAMES, Settings

log = logging.getLogger("lab_coach.policy")

LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")


@dataclass
class PolicyResult:
    allowed: bool
    reason: str
    # user-facing текст (без внутренних IP), log_detail (с IP для audit log)
    user_message: str = ""
    log_detail: str = ""
    resolved_ips: tuple[str, ...] = ()
    kind: str = "ip"  # ip | url | hostname


def parse_networks(cidr_raw: list[str]) -> list:
    nets = []
    for c in cidr_raw:
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            log.warning("bad CIDR ignored: %r", c)
    return nets


def ip_in_networks(ip: ipaddress._BaseAddress, nets: list) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def _is_loopback(ip: ipaddress._BaseAddress) -> bool:
    return ip.is_loopback


def _is_metadata_ip(ip: ipaddress._BaseAddress) -> bool:
    try:
        if ip.version == 4 and ip in LINK_LOCAL:
            return True
    except Exception:
        pass
    return False


def split_host_port(t: str) -> tuple[str, int | None]:
    """Разобрать 'host:port' (CTF-инстансы). Возвращает (host, port|None). Без '://'."""
    s = (t or "").strip()
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else None
        return s, None
    if s.count(":") == 1:
        h, p = s.split(":", 1)
        if h and p.isdigit():
            return h, int(p)
    return s, None


def normalize_scan_target(target: str) -> str:
    """Цель для сканера: 'host:port' без схемы → 'http://host:port'. Остальное как есть."""
    t = (target or "").strip()
    if t.lower().startswith(("http://", "https://")) or "://" in t:
        return t
    host, port = split_host_port(t)
    if port and host:
        return f"http://{host}:{port}"
    return t


def _spawned_host(s: Settings) -> str:
    sp = (s.spawned_target or "").strip()
    if not sp:
        return ""
    return split_host_port(sp)[0].strip().lower()


def check_ip_allowed(ip_str: str, s: Settings) -> PolicyResult:
    """Проверка одного IP-адреса. Никогда не показывает IP в user_message."""
    ip_str = (ip_str or "").strip()
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return PolicyResult(False, "bad_ip", "Цель не в lab-сети: некорректный IP.",
                            f"bad ip literal {ip_str!r}")

    # F-PLT-07: профиль hackthissite — любой скан deny
    if s.lab_platform == "hackthissite":
        return PolicyResult(False, "hackthissite_scan_denied",
                            "Профиль hackthissite: сканирование запрещено. Используйте explain_mission по тексту задания.",
                            f"hackthissite scan denied for {ip}")

    # HTB/CTF SPAWNED_TARGET: единственное исключение для global (один инстанс сессии).
    # SPAWNED_TARGET может быть с портом (IP:port) — сравниваем и валидируем host-часть.
    spawned = _spawned_host(s)
    if spawned and ip_str.strip().lower() == spawned:
        if s.lab_platform in ("htb", "ctf"):
            try:
                sip = ipaddress.ip_address(spawned)
            except ValueError:
                sip = None
            if sip is not None and not _is_metadata_ip(sip) and not sip.is_loopback:
                return PolicyResult(True, "spawned_target",
                                    "", f"SPAWNED_TARGET exception {ip}", kind="ip")
        # SPAWNED_TARGET задан, но не совпадает с платформой htb → дальше общий deny

    # F-POL-01: пустой CIDR → всё запрещено
    cidrs = s.effective_cidrs
    if not cidrs:
        if s.lab_platform == "hackthissite":
            return PolicyResult(False, "hackthissite_scan_denied",
                                "Профиль hackthissite: сканирование запрещено. Используйте explain_mission по тексту задания.",
                                f"hackthissite scan denied for {ip}")
        return PolicyResult(False, "empty_allowlist",
                            "Сканирование запрещено: список ALLOWED_LAB_CIDRS пуст.",
                            f"empty ALLOWED_LAB_CIDRS, target {ip}")

    # §10.2: metadata/link-local всегда запрещены
    if _is_metadata_ip(ip):
        return PolicyResult(False, "metadata_denied",
                            "Цель не в lab-сети: адрес запрещён (link-local/metadata).",
                            f"metadata/link-local denied {ip}")

    # Loopback по умолчанию запрещён
    if _is_loopback(ip) and not s.allow_loopback:
        return PolicyResult(False, "loopback_denied",
                            "Цель не в lab-сети: loopback запрещён (включите ALLOW_LOOPBACK=true только для отладки на своей машине).",
                            f"loopback denied {ip}")

    # F-POL-03: global deny даже при попадании в список
    try:
        if ip.is_global:
            return PolicyResult(False, "public_denied",
                                "Отказ: цель не в lab-сети. Публичные IP запрещены.",
                                f"public/global denied {ip}")
    except Exception:
        pass

    nets = parse_networks(cidrs)
    if not nets:
        return PolicyResult(False, "empty_allowlist",
                            "Сканирование запрещено: список ALLOWED_LAB_CIDRS пуст.",
                            f"no parseable CIDRs, target {ip}")
    if ip_in_networks(ip, nets):
        # F-POL-02 allow (после всех deny-проверок)
        return PolicyResult(True, "lab_allowed", "", f"allowed {ip} in lab CIDRs", kind="ip")
    return PolicyResult(False, "not_in_lab",
                        "Отказ: цель не в lab-сети.",
                        f"not in ALLOWED_LAB_CIDRS {ip}")


def resolve_host(host: str) -> list[str]:
    """getaddrinfo → список IP-строк. Пустой список = отказ выше."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    out: list[str] = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in out:
            out.append(ip)
    return out


def check_hostname_allowed(host: str, s: Settings, resolved: list[str] | None = None) -> PolicyResult:
    """F-POL-04: каждый A/AAAA должен попадать в lab CIDR, иначе отказ (anti-rebind)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return PolicyResult(False, "bad_host", "Цель не в lab-сети: пустое имя хоста.", "empty hostname", kind="hostname")
    if host in METADATA_HOSTNAMES:
        return PolicyResult(False, "metadata_denied",
                            "Цель не в lab-сети: адрес запрещён (metadata).",
                            f"metadata hostname denied {host}", kind="hostname")
    if s.lab_platform == "hackthissite":
        return PolicyResult(False, "hackthissite_scan_denied",
                            "Профиль hackthissite: сканирование запрещено. Используйте explain_mission по тексту задания.",
                            f"hackthissite scan denied host {host}", kind="hostname")
    ips = list(resolved) if resolved is not None else resolve_host(host)
    if not ips:
        return PolicyResult(False, "dns_empty",
                            "Цель не в lab-сети: имя не резолвится в lab-диапазон.",
                            f"DNS empty for {host}", kind="hostname")
    # Каждый адрес проверяем; хотя бы один non-lab → отказ (F-POL-05: IP только в лог)
    for ip_str in ips:
        r = check_ip_allowed(ip_str, s)
        # check_ip_allowed для hackthissite уже обработан; здесь общий случай:
        if not r.allowed:
            return PolicyResult(False, "dns_mixed_or_public",
                                "Цель не в lab-сети: имя резолвится за пределы lab.",
                                f"host {host} -> {ips} denied ({r.reason})",
                                resolved_ips=tuple(ips), kind="hostname")
    return PolicyResult(True, "lab_allowed", "", f"host {host} -> {ips} all in lab",
                        resolved_ips=tuple(ips), kind="hostname")


def check_target_allowed(target: str, s: Settings) -> PolicyResult:
    """Единая точка: IP | hostname | http(s) URL. F-POL-07 + делегирование."""
    t = (target or "").strip()
    if not t:
        return PolicyResult(False, "bad_target", "Цель не в lab-сети: пустая цель.", "empty target")
    if len(t) > 2048:
        return PolicyResult(False, "too_long",
                            "Отказ: слишком длинная цель (>2048).", f"target length {len(t)}")
    low = t.lower()
    if low.startswith(("http://", "https://")):
        return check_url_allowed(t, s)
    # CTF-инстансы вида host:port (без схемы)
    if "://" not in t:
        host, port = split_host_port(t)
        if port is not None:
            if not 1 <= port <= 65535:
                return PolicyResult(False, "bad_port",
                                    "Отказ: порт должен быть 1-65535.",
                                    f"bad port in {t[:80]!r}")
            if "@" in host:
                return PolicyResult(False, "userinfo_denied",
                                    "Отказ: userinfo в цели запрещён.", "userinfo in host:port")
            try:
                ipaddress.ip_address(host)
                r = check_ip_allowed(host, s)
            except ValueError:
                r = check_hostname_allowed(host, s)
            r.log_detail += f" port={port}"
            return r
    # голый IP?
    try:
        ipaddress.ip_address(t)
        return check_ip_allowed(t, s)
    except ValueError:
        pass
    # отказ очевидным URL-мусором
    if "://" in t:
        return PolicyResult(False, "bad_scheme",
                            "Отказ: разрешены только http(s) URL, IP или lab-имя хоста.",
                            f"bad scheme {t[:60]!r}")
    if "@" in t.split("/")[0]:
        return PolicyResult(False, "userinfo_denied",
                            "Отказ: userinfo в цели запрещён.", "userinfo in bare host")
    return check_hostname_allowed(t, s)


def check_url_allowed(url: str, s: Settings) -> PolicyResult:
    """F-POL-06/07: схема, userinfo, длина, хост → IP/hostname политика."""
    u = (url or "").strip()
    if len(u) > 2048:
        return PolicyResult(False, "too_long", "Отказ: слишком длинный URL (>2048).", "url too long")
    try:
        parts = urlsplit(u)
    except ValueError:
        return PolicyResult(False, "bad_url", "Отказ: некорректный URL.", f"bad url {u[:80]!r}")
    if parts.scheme not in ("http", "https"):
        return PolicyResult(False, "bad_scheme",
                            "Отказ: разрешены только http(s) URL.",
                            f"scheme {parts.scheme!r}", kind="url")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        return PolicyResult(False, "userinfo_denied",
                            "Отказ: userinfo в URL запрещён.", "userinfo in url", kind="url")
    host = (parts.hostname or "").strip()
    if not host:
        return PolicyResult(False, "bad_url", "Отказ: в URL нет хоста.", f"no host {u[:80]!r}", kind="url")
    if host.lower() in METADATA_HOSTNAMES:
        return PolicyResult(False, "metadata_denied",
                            "Цель не в lab-сети: адрес запрещён (metadata).",
                            f"metadata host in url {host}", kind="url")
    try:
        ipaddress.ip_address(host)
        r = check_ip_allowed(host, s)
        r.kind = "url"
        return r
    except ValueError:
        pass
    r = check_hostname_allowed(host, s)
    r.kind = "url"
    return r


def check_redirect_allowed(url: str, s: Settings) -> PolicyResult:
    """F-POL-06: редирект на non-lab URL/IP → стоп. Проверять каждый Location."""
    return check_url_allowed(url, s)


def check_redirect_chain(url: str, s: Settings, *, max_hops: int = 5) -> dict:
    """HEAD без follow: каждый Location через LabPolicy. Не логинимся."""
    notes: list[str] = []
    try:
        import httpx  # type: ignore
    except ImportError:
        notes.append("Проверка редиректов пропущена (нет httpx).")
        return {"notes": notes, "blocked": "", "blocked_detail": ""}
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as c:
            cur = url
            for _ in range(max_hops):
                r = c.head(cur)
                if r.status_code not in (301, 302, 303, 307, 308):
                    return {"notes": notes, "blocked": "", "blocked_detail": ""}
                loc = r.headers.get("location", "")
                if not loc:
                    return {"notes": notes, "blocked": "", "blocked_detail": ""}
                nxt_abs = urljoin(cur, loc)
                v = check_url_allowed(nxt_abs, s)
                if not v.allowed:
                    return {"notes": notes,
                            "blocked": "Редирект ведёт за пределы lab-сети — остановлено.",
                            "blocked_detail": f"{v.reason}; {v.log_detail}"}
                cur = nxt_abs
            notes.append("Цепочка редиректов длиннее 5 — остановлено на lab-проверке.")
            return {"notes": notes, "blocked": "", "blocked_detail": ""}
    except Exception as e:
        notes.append(f"Проверка редиректов не удалась ({type(e).__name__}) — скан продолжен по исходной lab-цели.")
        return {"notes": notes, "blocked": "", "blocked_detail": ""}


AUTH_REQUEST_HINTS = (
    "вход без пароля", "войти без пароля", "без пароля",
    "сменить пароль", "смена пароля", "поставить пароль", "поменять пароль",
    "change password", "set password", "reset password", "login without password",
    "auth bypass", "обход авторизации", "обход аутентификации", "sql injection login",
    "подмена сессии", "украсть сессию",
)


def looks_like_auth_attack_request(text: str) -> bool:
    t = (text or "").lower()
    return any(h in t for h in AUTH_REQUEST_HINTS)


AUTH_REFUSAL_RU = (
    "Отказ: Lab Coach не выполняет вход на цели и не меняет пароли "
    "(в том числе «вход без пароля» и установку пароля на удалённой системе). "
    "Свой пароль меняйте штатно: админка CMS / панель хостинга / phpMyAdmin владельца. "
    "Могу объяснить класс уязвимости и что почитать для lab."
)
