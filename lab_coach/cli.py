"""CLI Lab Coach: scan / explain / import-scanbot / doctor. Русский интерфейс."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from urllib.parse import urlsplit

from . import __version__
from .audit import init_db, log_event
from .config import load_settings, require_admin_configured
from .explain import finding_danger, refusal_for, summarize
from .importer import extract_findings, load_scanbot_report, report_meta
from .llm import resolve_endpoint
from .platforms import capabilities
from .policy import (AUTH_REFUSAL_RU, check_target_allowed,
                     looks_like_auth_attack_request)
from .ratelimit import check_rate_limit
from .reports import write_report
from .scanners import run_lab_scanners

DISCLAIMER = (
    "Lab Coach — только lab: сканируются лишь адреса вашей учебной сети (RFC1918/ULA/lab CIDR). "
    "Публичные IP отклоняются. Эксплойты не запускаются. Продукт не логинится и не меняет пароли. "
    "Цели: ваши VM либо официальный полигон в рамках правил площадки "
    "(TryHackMe / Hack The Box / Standoff 365 учения / Hack This Site миссии / VulnHub / Metasploitable в своей VM)."
)


def _setup_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format="%(levelname)s %(name)s: %(message)s")


def _target_label(target: str) -> str:
    """Метка цели для отчётов: хост без userinfo/портов-секретов."""
    t = target.strip()
    if t.lower().startswith(("http://", "https://")):
        try:
            p = urlsplit(t)
            return f"{p.scheme}://{p.hostname or '?'}"
        except ValueError:
            return "url"
    return t.split("/")[0][:120]


# ---------- scan ----------

def cmd_scan(args) -> int:
    s = load_settings()
    _setup_logging(s.log_level)
    print(DISCLAIMER)
    try:
        require_admin_configured(s)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    init_db(s.database_url)
    user = "cli"

    target = args.target.strip()
    # UC-6: просьбы вида «войти без пароля / сменить пароль» — отказ + audit
    if looks_like_auth_attack_request(target) or (args.extra and looks_like_auth_attack_request(" ".join(args.extra))):
        log_event(s.database_url, user=user, action="auth_action_denied", target=target[:200],
                  detail="auth-like scan request refused")
        print(AUTH_REFUSAL_RU)
        return 3

    # Одна цель на вызов: списки/CIDR через запятую/пробел запрещены (§22)
    if "," in target or any(sep in target for sep in (" ", "\n", "\t")):
        log_event(s.database_url, user=user, action="scan_denied", target=target[:200],
                  detail="multiple targets / subnet scan refused: one target per call")
        print("Отказ: одна цель на вызов. Списки и подсети запрещены (укажите один IP/URL из брифа).")
        return 3
    if "/" in target and not target.lower().startswith(("http://", "https://")):
        # Похоже на CIDR
        log_event(s.database_url, user=user, action="scan_denied", target=target[:200],
                  detail="cidr/subnet scan refused")
        print("Отказ: сканирование подсетей запрещено. Укажите один IP из брифа.")
        return 3

    ok_rate, used = check_rate_limit(s.database_url, s.max_scans_per_hour)
    if not ok_rate:
        log_event(s.database_url, user=user, action="scan_denied", target=target[:200],
                  detail=f"rate limit {used}/{s.max_scans_per_hour} per hour")
        print(f"Отказ: лимит {s.max_scans_per_hour} сканов/час исчерпан. Подождите.")
        return 3

    # REQUIRE_VPN предупреждение (F-PLT-03)
    if s.lab_platform in ("thm", "htb") and s.require_vpn:
        from .platforms import vpn_guess
        if not vpn_guess()["likely_vpn"]:
            print("Предупреждение: профиль {} а локальных адресов tun/tap в 10/8 нет — "
                  "похоже, VPN выключен. Подключите .ovpn, иначе скан уйдёт в пустоту.".format(s.lab_platform))

    verdict = check_target_allowed(target, s)
    if not verdict.allowed:
        log_event(s.database_url, user=user, action="scan_denied", target=target[:200],
                  detail=f"{verdict.reason}; {verdict.log_detail}")
        print(f"Отказ: {verdict.user_message or 'цель не в lab-сети.'}")
        return 3

    job = run_lab_scanners(target, s)
    if job.get("blocked"):
        log_event(s.database_url, user=user, action="scan_denied", target=_target_label(target),
                  detail=f"redirect denied; {job.get('blocked_detail', '')}")
        print(f"Отказ: {job['blocked']}")
        return 3
    notes: list[str] = list(job.get("notes") or [])
    findings: list[dict] = list(job.get("findings") or [])
    final_target = job.get("final_target") or target
    nuc_status = job.get("nuclei_status", "")

    dangers = [finding_danger(f) for f in findings]
    _base, _key, _model = resolve_endpoint(s)
    summary_md, origin = summarize(findings, "lab", llm_enabled=s.llm_enabled,
                                   base_url=_base, api_key=_key, model=_model)
    if notes:
        summary_md += "\n_Заметки запуска:_ " + "; ".join(notes) + "\n"

    rep = write_report(reports_dir=os.path.join("data", "reports"), target_label=_target_label(final_target),
                       findings=findings, dangers=dangers, summary_md=summary_md,
                       summary_origin=origin, meta={"notes": notes, "nuclei_status": nuc_status})
    log_event(s.database_url, user=user, action="scan_ok", target=_target_label(final_target),
              scan_id=f"scan-{rep['scan_id']}", detail=f"{len(findings)} findings; {origin}")
    print(f"Готово: scan-{rep['scan_id']} ({len(findings)} находок). Файлы: {rep['dir']}")
    return 0


# ---------- explain / import ----------

def cmd_explain(args) -> int:
    s = load_settings()
    _setup_logging(s.log_level)
    print(DISCLAIMER)
    try:
        require_admin_configured(s)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    init_db(s.database_url)
    path = args.report
    try:
        report = load_scanbot_report(path)
    except (OSError, ValueError) as e:
        print(f"Не могу прочитать JSON: {e}")
        return 2
    findings = extract_findings(report)
    meta = report_meta(report, path)
    # F-IMP-02: на location не ходим — только текст. Маскирование — внутри summarize.
    dangers = [finding_danger(f) for f in findings]
    _base, _key, _model = resolve_endpoint(s)
    summary_md, origin = summarize(findings, "imported_report", llm_enabled=s.llm_enabled,
                                   base_url=_base, api_key=_key, model=_model)
    rep = write_report(reports_dir=os.path.join("data", "reports"),
                       target_label=f"import:{meta.get('source_file','report')}",
                       findings=findings, dangers=dangers, summary_md=summary_md,
                       summary_origin=origin, meta={"imported_from": meta})
    log_event(s.database_url, user="cli", action="explain_ok", target=meta.get("source_file","")[:200],
              scan_id=f"scan-{rep['scan_id']}", detail=f"{len(findings)} findings from import; {origin}")
    print(f"Готово: import разобран → scan-{rep['scan_id']} ({len(findings)} находок). Файлы: {rep['dir']}")
    return 0


def cmd_doctor(_args) -> int:
    s = load_settings()
    _setup_logging(s.log_level)
    caps = capabilities(s)
    print(f"Lab Coach v{__version__} — doctor (без секретов)")
    print(DISCLAIMER)
    print(json.dumps(caps, ensure_ascii=False, indent=2))
    if not s.admin_ids:
        print("ВНИМАНИЕ: ADMIN_IDS пуст — scan/explain не стартуют (fail-closed).")
    if caps.get("cidr_too_wide_warn"):
        print("ВНИМАНИЕ: lab CIDR шире /16 — сузьте до host-only /24 или диапазона комнаты (см. README).")
    if s.lab_platform in ("thm", "htb") and not caps["vpn_guess"]["likely_vpn"]:
        print("ВНИМАНИЕ: профиль {} без признаков VPN (нет 10/8 локально). Подключите .ovpn.".format(s.lab_platform))
    if s.lab_platform == "hackthissite":
        print("Профиль hackthissite: сканирование запрещено, доступен только разбор текста миссии.")
    return 0


def cmd_auth_denied(args) -> int:
    s = load_settings()
    _setup_logging(s.log_level)
    init_db(s.database_url)
    what = getattr(args, "rest", "") or ""
    log_event(s.database_url, user="cli", action="auth_action_denied",
              target=str(what)[:200], detail=f"refused CLI auth action: {args._denied_name}")
    print("Нет такого действия. " + AUTH_REFUSAL_RU)
    return 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lab-coach", description="Lab Coach — учебный ассистент для изолированного полигона")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="Сканировать lab-цель (один IP/URL)")
    sc.add_argument("target", help="IP или http(s) URL в lab-сети")
    sc.add_argument("extra", nargs="*", help=argparse.SUPPRESS)
    sc.set_defaults(func=cmd_scan)
    ex = sub.add_parser("explain", help="Разобрать JSON-отчёт без сети к цели")
    ex.add_argument("report", help="Путь к scan-*.json (свой или security-scan-bot)")
    ex.set_defaults(func=cmd_explain)
    im = sub.add_parser("import-scanbot", help="Импорт JSON security-scan-bot (алиас explain)")
    im.add_argument("report", help="Путь к scan-*.json прод-бота")
    im.set_defaults(func=cmd_explain)
    d = sub.add_parser("doctor", help="Проверка capabilities без секретов")
    d.set_defaults(func=cmd_doctor)
    # Запрещённые действия: явный отказ + audit (приёмка §15)
    for name in ("login", "set-password", "set_password", "change-password",
                 "change_password", "reset-password", "reset_password", "auth-bypass"):
        h = sub.add_parser(name, help=argparse.SUPPRESS)
        h.add_argument("rest", nargs="?", default="")
        h.set_defaults(func=cmd_auth_denied, _denied_name=name)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except SystemExit as e:
        # require_admin_configured уже напечатал причину
        code = e.code if isinstance(e.code, int) else 2
        return code


if __name__ == "__main__":
    raise SystemExit(main())
