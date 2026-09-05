"""Telegram-бот Lab Coach (этап L2, опционально). Другой бот, другой токен.

Запуск: BOT_TOKEN=... ADMIN_IDS=... python -m lab_coach.tg
Требуется aiogram (pip install lab-coach[tg]). Те же политики LabPolicy.
"""
from __future__ import annotations

import logging

log = logging.getLogger("lab_coach.tg")

HELP = (
    "Lab Coach (только lab).\n"
    "Команды:\n"
    "/start — дисклеймер\n"
    "/scan 192.168.56.10 — скан lab-IP/URL (одна цель)\n"
    "/explain — пришлите JSON scan-*.json файлом\n"
    "/status — capabilities без секретов\n"
    "Публичные IP отклоняются. Входы и смена паролей запрещены."
)


def main() -> int:
    from .config import load_settings
    s = load_settings()
    logging.basicConfig(level=getattr(logging, s.log_level.upper(), logging.INFO))
    if not s.admin_ids:
        print("ADMIN_IDS пуст — Telegram не стартует (fail-closed).")
        return 2
    if not s.bot_token:
        print("BOT_TOKEN пуст — Telegram не стартует. Этап L2 опционален, CLI/MCP работают.")
        return 2
    try:
        import asyncio
        from aiogram import Bot, Dispatcher, F
        from aiogram.types import Message
    except ImportError:
        print("Нужен aiogram: pip install 'lab-coach[tg]'")
        return 2

    from .audit import init_db, log_event
    from .explain import finding_danger, summarize
    from .llm import resolve_endpoint as _resolve_endpoint
    from .importer import extract_findings, load_scanbot_report, report_meta
    from .platforms import capabilities
    from .policy import AUTH_REFUSAL_RU, looks_like_auth_attack_request, check_target_allowed
    from .reports import write_report
    import json as _json
    import os as _os
    import tempfile as _tf

    init_db(s.database_url)
    bot = Bot(s.bot_token)
    dp = Dispatcher()

    def is_admin(uid: int) -> bool:
        return str(uid) in s.admin_ids

    @dp.message(F.text.startswith("/start"))
    async def start(m: Message):
        if not is_admin(m.from_user.id):
            return await m.answer("Нет доступа.")
        await m.answer("Lab Coach — только lab: частные IP ваших VM/полигона. Публичные IP отклоняются. "
                       "Эксплойты не запускаются. Продукт не логинится и не меняет пароли.\n\n" + HELP)

    @dp.message(F.text.startswith("/status"))
    async def status(m: Message):
        if not is_admin(m.from_user.id):
            return await m.answer("Нет доступа.")
        await m.answer(_json.dumps(capabilities(s), ensure_ascii=False, indent=2)[:3500])

    @dp.message(F.text.startswith("/scan"))
    async def scan(m: Message):
        if not is_admin(m.from_user.id):
            return await m.answer("Нет доступа.")
        parts = (m.text or "").split(maxsplit=1)
        if len(parts) < 2:
            return await m.answer("Использование: /scan 192.168.56.10")
        target = parts[1].strip()
        if looks_like_auth_attack_request(target):
            log_event(s.database_url, user=str(m.from_user.id), action="auth_action_denied",
                      target=target[:200], detail="tg auth-like refused")
            return await m.answer(AUTH_REFUSAL_RU)
        v = check_target_allowed(target, s)
        if not v.allowed:
            log_event(s.database_url, user=str(m.from_user.id), action="scan_denied",
                      target=target[:200], detail=f"{v.reason}; {v.log_detail}")
            return await m.answer(f"Отказ: {v.user_message}")
        from .scanners import run_nuclei
        nuc = run_nuclei(target, s.nuclei_path, s.scan_timeout_seconds)
        findings = list(nuc.get("findings", []))
        dangers = [finding_danger(f) for f in findings]
        _base, _key, _model = _resolve_endpoint(s)
        summary_md, origin = summarize(findings, "lab", llm_enabled=s.llm_enabled,
                                       base_url=_base, api_key=_key, model=_model)
        rep = write_report(reports_dir=_os.path.join("data", "reports"), target_label=target[:120],
                           findings=findings, dangers=dangers, summary_md=summary_md,
                           summary_origin=origin, meta={"via": "tg"})
        log_event(s.database_url, user=str(m.from_user.id), action="scan_ok", target=target[:200],
                  scan_id=f"scan-{rep['scan_id']}", detail=f"{len(findings)}; {origin}")
        await m.answer(f"Готово: scan-{rep['scan_id']} ({len(findings)} находок).\n{summary_md[:3000]}")

    @dp.message(F.document)
    async def doc(m: Message):
        if not is_admin(m.from_user.id):
            return await m.answer("Нет доступа.")
        if not (m.document.file_name or "").endswith(".json"):
            return await m.answer("Пришлите scan-*.json")
        with _tf.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            await bot.download(m.document, destination=tf.name)
            path = tf.name
        try:
            report = load_scanbot_report(path)
        except ValueError:
            return await m.answer("Не JSON.")
        findings = extract_findings(report)
        meta = report_meta(report, m.document.file_name)
        dangers = [finding_danger(f) for f in findings]
        _base, _key, _model = _resolve_endpoint(s)
        summary_md, origin = summarize(findings, "imported_report", llm_enabled=s.llm_enabled,
                                       base_url=_base, api_key=_key, model=_model)
        rep = write_report(reports_dir=_os.path.join("data", "reports"),
                           target_label=f"import:{meta.get('source_file','report')}",
                           findings=findings, dangers=dangers, summary_md=summary_md,
                           summary_origin=origin, meta={"via": "tg"})
        log_event(s.database_url, user=str(m.from_user.id), action="explain_ok",
                  target=meta.get("source_file","")[:200], scan_id=f"scan-{rep['scan_id']}",
                  detail=f"{len(findings)}; {origin}")
        await m.answer(f"Разобрано → scan-{rep['scan_id']}.\n{summary_md[:3000]}")

    async def run():
        await dp.start_polling(bot)

    import asyncio as _a
    _a.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
