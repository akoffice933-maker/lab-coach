"""Rate limit: MAX_SCANS_PER_HOUR — одна цель на вызов (§22)."""
from __future__ import annotations

import time

from .audit import recent

WINDOW = 3600


def scans_in_last_hour(database_url: str) -> int:
    now = int(time.time())
    n = 0
    for row in recent(database_url, limit=500):
        if row.get("action") in ("scan_ok", "scan_denied") and (now - int(row.get("ts", 0))) < WINDOW:
            n += 1
    return n


def check_rate_limit(database_url: str, max_per_hour: int) -> tuple[bool, int]:
    n = scans_in_last_hour(database_url)
    return (n < max_per_hour, n)
