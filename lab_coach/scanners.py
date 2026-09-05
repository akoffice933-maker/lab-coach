"""Запуск сканеров lab-цели: Nuclei + опциональный nmap. shell=False, argv списком."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess

log = logging.getLogger("lab_coach.scanners")


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_nuclei(target: str, nuclei_path: str = "nuclei", timeout: int = 900) -> dict:
    """Nuclei по -u lab-цели (F-SCN-01/02/05). Возвращает dict(step...)."""
    binary = nuclei_path or "nuclei"
    if not tool_available(binary):
        return {"scanner": "nuclei", "status": "skipped",
                "note": f"Сканер {binary!r} не найден в PATH — шаг пропущен, job продолжается."}
    # Только -u <цель>, JSON-вывод; никаких exploit-флагов.
    argv = [binary, "-u", target, "-jsonl", "-silent"]
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
    argv = ["nmap", "-sV", "-T4", "--top-ports", "50", target_host]
    try:
        p = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"scanner": "nmap", "status": "timeout", "note": "nmap превысил таймаут."}
    except Exception as e:
        return {"scanner": "nmap", "status": "error", "note": f"nmap не запустился: {type(e).__name__}"}
    return {"scanner": "nmap", "status": "ok", "raw_tail": (p.stdout or "")[-4000:]}
