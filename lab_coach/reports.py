"""Экспорт отчётов: data/reports/scan-<id>/ : JSON, MD, HTML (F-RPT-01/03)."""
from __future__ import annotations

import html
import json
import os
import time


def _next_id(reports_dir: str) -> str:
    os.makedirs(reports_dir, exist_ok=True)
    best = 0
    for name in os.listdir(reports_dir):
        if name.startswith("scan-"):
            try:
                best = max(best, int(name.split("-", 1)[1].split("_")[0]))
            except ValueError:
                continue
    return str(best + 1)


def write_report(*, reports_dir: str, target_label: str, findings: list[dict],
                 dangers: list[str], summary_md: str, summary_origin: str,
                 meta: dict | None = None, scan_id: str | None = None) -> dict:
    sid = scan_id or _next_id(reports_dir)
    d = os.path.join(reports_dir, f"scan-{sid}")
    os.makedirs(d, exist_ok=True)

    payload = {
        "scan_id": sid,
        "target_label": target_label,
        "created_at": int(time.time()),
        "summary_origin": summary_origin,
        "meta": meta or {},
        "findings": findings,
    }
    with open(os.path.join(d, f"scan-{sid}.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    md = _render_md(sid, target_label, findings, dangers, summary_md, summary_origin)
    with open(os.path.join(d, f"scan-{sid}.md"), "w", encoding="utf-8") as f:
        f.write(md)

    h = _render_html(sid, target_label, findings, dangers, summary_md, summary_origin)
    with open(os.path.join(d, f"scan-{sid}.html"), "w", encoding="utf-8") as f:
        f.write(h)

    return {"scan_id": sid, "dir": d,
            "files": [f"scan-{sid}.json", f"scan-{sid}.md", f"scan-{sid}.html"]}


def _render_md(sid, target_label, findings, dangers, summary_md, origin) -> str:
    L = [f"# Lab Coach — отчёт scan-{sid}", "",
         f"**Цель (метка):** `{target_label}`",
         f"**Саммари:** {origin}", "",
         "## Учебное саммари", "", summary_md.strip(), "",
         "## Находки", ""]
    if not findings:
        L.append("Находок нет.")
    for i, f in enumerate(findings):
        L += [f"### {i+1}. {f.get('title','(без названия)')} [{f.get('severity','info')}]", "",
              f"- Сканер: `{f.get('scanner','')}`",
              f"- Где: `{f.get('location','')}`"]
        if f.get("description"):
            L.append(f"- Описание: {f['description']}")
        if f.get("impact"):
            L.append(f"- Влияние: {f['impact']}")
        L += [f"- **Чем опасно:** {(dangers[i] if i < len(dangers) else '')}", ""]
    L += ["---", "_Только lab. Эксплойты не запускаются. Продукт не логинится и не меняет пароли._"]
    return "\n".join(L) + "\n"


def _render_html(sid, target_label, findings, dangers, summary_md, origin) -> str:
    def e(s):
        return html.escape(str(s or ""))
    rows = []
    for i, f in enumerate(findings):
        rows.append(
            f"<section><h3>{i+1}. {e(f.get('title'))} [{e(f.get('severity'))}]</h3>"
            f"<p><b>Сканер:</b> {e(f.get('scanner'))} · <b>Где:</b> <code>{e(f.get('location'))}</code></p>"
            + (f"<p>{e(f.get('description'))}</p>" if f.get("description") else "")
            + f"<p><b>Чем опасно:</b> {e(dangers[i] if i < len(dangers) else '')}</p></section>")
    head = ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            + "<title>Lab Coach scan-" + e(sid) + "</title>"
            + "<style>body{font-family:sans-serif;max-width:860px;margin:2em auto;padding:0 1em}"
              "section{border:1px solid #ddd;border-radius:8px;padding:1em;margin:1em 0}"
              "code{background:#f4f4f4;padding:2px 4px;border-radius:4px}</style></head><body>")
    body = (f"<h1>Lab Coach — отчёт scan-{e(sid)}</h1>"
            + f"<p><b>Цель (метка):</b> <code>{e(target_label)}</code> · <b>Саммари:</b> {e(origin)}</p>"
            + f"<h2>Учебное саммари</h2><pre style='white-space:pre-wrap'>{e(summary_md.strip())}</pre>"
            + f"<h2>Находки ({len(findings)})</h2>"
            + ("".join(rows) if rows else "<p>Находок нет.</p>")
            + "<hr><p><i>Только lab. Эксплойты не запускаются. Продукт не логинится и не меняет пароли.</i></p>"
            + "</body></html>")
    return head + body
