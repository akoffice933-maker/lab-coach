"""Импорт JSON-отчётов security-scan-bot (F-IMP-01/02/03): без сети к цели."""
from __future__ import annotations

import json
import os


def load_scanbot_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def extract_findings(report: dict) -> list[dict]:
    """Формат scan-*.json: поля result.findings[]: scanner, severity, title, description, location, impact."""
    if isinstance(report.get("result"), dict) and isinstance(report["result"].get("findings"), list):
        raw = report["result"]["findings"]
    elif isinstance(report.get("findings"), list):
        raw = report["findings"]
    else:
        raw = []
    out: list[dict] = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        out.append({
            "scanner": str(f.get("scanner", "scan-bot")),
            "severity": str(f.get("severity", "info")).lower(),
            "title": str(f.get("title", "(без названия)")),
            "description": str(f.get("description", "")),
            "location": str(f.get("location", "")),
            "impact": str(f.get("impact", "")),
        })
    return out


def report_meta(report: dict, path: str) -> dict:
    r = report.get("result", {}) if isinstance(report.get("result"), dict) else {}
    return {
        "source_file": os.path.basename(path),
        "scan_id": str(report.get("scan_id", r.get("scan_id", ""))),
        "target": str(report.get("target", r.get("target", ""))),
        "created": str(report.get("created_at", r.get("created_at", ""))),
    }
