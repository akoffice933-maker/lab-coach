"""Запуск сканеров lab-цели: Nuclei + опциональный nmap. shell=False, argv списком."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess

log = logging.getLogger("lab_coach.scanners")

# Nuclei: без OOB (interactsh) и без exploit/intrusive/dos шаблонов.
NUCLEI_EXCLUDE_TAGS = "exploit,intrusive,dos"


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_nuclei(target: str, nuclei_path: str = "nuclei", timeout: int = 900) -> dict:
    """Nuclei по -u lab-цели (F-SCN-01/02/05). Возвращает dict(step...)."""
    binary = nuclei_path or "nuclei"
    if not tool_available(binary):
        return {"scanner": "nuclei", "status": "skipped",
                "note": f"Сканер {binary!r} не найден в PATH — шаг пропущен, job продолжается."}
    # Только -u <цель>, JSON-вывод; без interactsh и exploit/intrusive/dos.
    argv = [binary, "-u", target, "-jsonl", "-silent",
            "-ni", "-etags", NUCLEI_EXCLUDE_TAGS]
    try:
        p = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"scanner": "nuclei", "status": "timeout",
                "note": f"Nuclei превысил таймаут {timeout}c."}
    except Exception as e:
        return {"scanner": "nuclei", "status": "error", "note": f"Nuclei не запустился: {type(e).__name__}"}
    findings: list[dict] = []
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        findings.append({
            "scanner": "nuclei",
            "severity": str(obj.get("info", {}).get("severity", "info")).lower(),
            "title": str(obj.get("info", {}).get("name", obj.get("template-id", "nuclei finding"))),
            "description": str(obj.get("info", {}).get("description", "")),
            "location": str(obj.get("matched-at", target)),
            "impact": "",
            "template": str(obj.get("template-id", "")),
        })
    status = "ok" if p.returncode in (0,) else ("ok_no_matches" if not findings else "ok")
    return {"scanner": "nuclei", "status": status, "findings": findings,
            "stderr_tail": (p.stderr or "")[-2000:]}


def run_nmap(target_host: str, timeout: int = 900) -> dict:
    """Опциональный nmap: только -sV -T4 --top-ports (F-SCN-03)."""
    if not tool_available("nmap"):
        return {"scanner": "nmap", "status": "skipped",
                "note": "nmap не найден в PATH — шаг пропущен."}
    argv = ["nmap", "-sV", "-T4", "--top-ports", "50", "--", target_host]
    try:
        p = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"scanner": "nmap", "status": "timeout", "note": "nmap превысил таймаут."}
    except Exception as e:
        return {"scanner": "nmap", "status": "error", "note": f"nmap не запустился: {type(e).__name__}"}
    return {"scanner": "nmap", "status": "ok", "raw_tail": (p.stdout or "")[-4000:]}


def run_lab_scanners(target: str, s) -> dict:
    """Nuclei + опциональный nmap по уже разрешённой lab-цели."""
    from urllib.parse import urlsplit
    from .policy import check_redirect_chain, normalize_scan_target

    notes: list[str] = []
    final_target = normalize_scan_target(target)
    kind = "url" if final_target.lower().startswith(("http://", "https://")) else "ip"
    if kind == "url":
        red = check_redirect_chain(final_target, s)
        notes.extend(red.get("notes") or [])
        if red.get("blocked"):
            return {"blocked": red["blocked"], "blocked_detail": red.get("blocked_detail", ""),
                    "notes": notes, "findings": [], "nuclei_status": "denied"}

    nuc = run_nuclei(final_target, s.nuclei_path, s.scan_timeout_seconds)
    findings: list[dict] = list(nuc.get("findings", []))
    if nuc["status"] == "skipped":
        notes.append(nuc["note"])
    elif nuc["status"] in ("timeout", "error"):
        notes.append(nuc.get("note", "nuclei issue"))

    if s.nmap_enabled:
        host = ""
        t = final_target.strip()
        if t.lower().startswith(("http://", "https://")):
            try:
                host = urlsplit(t).hostname or ""
            except ValueError:
                host = ""
        else:
            host = t.split("/")[0]
            if host.count(":") == 1 and host.split(":")[1].isdigit():
                host = host.split(":")[0]
        if host:
            nm = run_nmap(host, s.scan_timeout_seconds)
            if nm["status"] == "skipped":
                notes.append(nm["note"])
            elif nm.get("raw_tail"):
                findings.append({"scanner": "nmap", "severity": "info",
                                 "title": "Открытые порты/версии (nmap -sV)",
                                 "description": nm["raw_tail"][-1500:],
                                 "location": host, "impact": ""})
    else:
        notes.append("nmap выключен (NMAP_ENABLED=false).")

    return {"blocked": "", "blocked_detail": "", "notes": notes,
            "findings": findings, "nuclei_status": nuc["status"],
            "final_target": final_target}
