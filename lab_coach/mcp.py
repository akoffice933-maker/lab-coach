"""MCP stdio-сервер Lab Coach (§22). Только transport=stdio.

Tools (закрытый список): get_lab_status, set_platform, scan_lab_target,
explain_mission, explain_report, import_scanbot_report.
Запрещённые (run_exploit, msf_*, shell, login, set_password...) НЕ реализованы.
"""
from __future__ import annotations

import json
import logging
import os
import sys

from . import __version__
from .audit import init_db, log_event
from .coach import get_ctf_playbook as _ctf_playbook
from .coach import get_plan_step as _plan_step
from .coach import get_role_brief as _role_brief
from .coach import harden_checklist as _harden
from .coach import init_session as _init_session
from .coach import log_note as _log_note
from .coach import read_session_file as _read_file
from .coach import session_status as _session_status
from .coach import verify_fix as _verify_fix
from .config import VALID_PLATFORMS, load_settings, require_admin_configured, write_runtime_state
from .explain import finding_danger, refusal_for, summarize
from .importer import extract_findings, load_scanbot_report, report_meta
from .llm import chat_completion as _chat_completion
from .llm import llm_configured, resolve_endpoint
from .platforms import capabilities
from .policy import AUTH_REFUSAL_RU, looks_like_auth_attack_request, check_target_allowed
from .ratelimit import check_rate_limit
from .reports import write_report

log = logging.getLogger("lab_coach.mcp")

FORBIDDEN_TOOLS = ("run_module", "exploit", "msf_console", "msf_rpc", "exec", "shell",
                   "fetch_url", "login", "set_password", "change_password", "reset_password",
                   "run_kaligpt", "run_pentestgpt", "pentestgpt")


def refuse_non_stdio() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport != "stdio":
        raise SystemExit(f"MCP: разрешён только transport=stdio (получено {transport!r}).")
    if os.environ.get("FASTMCP_HOST"):
        raise SystemExit("MCP: FASTMCP_HOST запрещён — сервер только stdio на машине полигона.")


TOOL_DEFS = [
    {"name": "get_lab_status", "description": "Статус lab: платформа, CIDR, VPN-guess, сканеры (без секретов).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "set_platform", "description": "Сменить профиль площадки. Пишет env процесса и data/runtime-state.json (переживает рестарт MCP).",
     "inputSchema": {"type": "object", "properties": {"platform": {"type": "string"}}, "required": ["platform"]}},
    {"name": "scan_lab_target", "description": "Сканировать ОДНУ lab-цель (IP/URL). Списки и подсети запрещены.",
     "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "explain_mission", "description": "Разобрать текст миссии/комнаты как преподаватель (без payload).",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "explain_report", "description": "Объяснить findings (inline JSON) без сети к цели.",
     "inputSchema": {"type": "object", "properties": {"findings": {"type": "array"}}}},
    {"name": "import_scanbot_report", "description": "Импортировать scan-*.json прод-бота без повторного скана.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "init_session", "description": "Начать сессию методологии: каталог ~/HTB/<machine>, scope на ОДНУ lab-цель.",
     "inputSchema": {"type": "object", "properties": {"machine": {"type": "string"}, "target": {"type": "string"}}, "required": ["machine", "target"]}},
    {"name": "session_status", "description": "Статус сессии: файлы, готовность шагов 0-6, что делать дальше.",
     "inputSchema": {"type": "object", "properties": {"machine": {"type": "string"}}, "required": ["machine"]}},
    {"name": "log_note", "description": "Дописать заметку в notes.md сессии (шаг 0-6).",
     "inputSchema": {"type": "object", "properties": {"machine": {"type": "string"}, "step": {"type": "string"}, "text": {"type": "string"}}, "required": ["machine", "step", "text"]}},
    {"name": "get_plan_step", "description": "Методология шага 0-6 (recon-команды, чек-листы; без пейлоадов).",
     "inputSchema": {"type": "object", "properties": {"step": {"type": "string"}, "target": {"type": "string"}}, "required": ["step"]}},
    {"name": "read_session_file", "description": "Прочитать файл сессии (nmap-вывод, notes) — только внутри каталога сессии.",
     "inputSchema": {"type": "object", "properties": {"machine": {"type": "string"}, "path": {"type": "string"}}, "required": ["machine", "path"]}},
    {"name": "get_role_brief", "description": "Бриф твоей роли (red/blue/coach): задача и правила учений.",
     "inputSchema": {"type": "object", "properties": {"role": {"type": "string"}}}},
    {"name": "harden_checklist", "description": "[blue] Чек-лист закрытия находки + как проверить.",
     "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}, "description": {"type": "string"}}, "required": ["title"]}},
    {"name": "verify_fix", "description": "[blue] Повторный скан СВОЕЙ lab-цели + сравнение с baseline-отчётом.",
     "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "baseline": {"type": "string"}}, "required": ["target", "baseline"]}},
    {"name": "get_ctf_playbook", "description": "Триаж CTF-категории (web/pwn/crypto/forensics/reversing/misc/osint/blockchain) + правила.",
     "inputSchema": {"type": "object", "properties": {"category": {"type": "string"}}}},
]

# Матрица ролей Red vs Blue (coach = всё). Платформу задаёт человек в env.
ADMIN_TOOLS = {
    "set_platform", "scan_lab_target", "explain_mission", "explain_report",
    "import_scanbot_report", "init_session", "verify_fix",
}

ROLE_TOOLS: dict[str, set[str] | None] = {
    "coach": None,
    "red": {"get_lab_status", "scan_lab_target", "explain_report",
            "init_session", "session_status", "log_note",
            "get_plan_step", "get_ctf_playbook", "read_session_file", "get_role_brief"},
    "blue": {"get_lab_status", "explain_report", "verify_fix", "harden_checklist",
             "init_session", "session_status", "log_note", "get_ctf_playbook",
             "read_session_file", "get_role_brief"},
}


def role_allowed(tool: str) -> tuple[bool, str]:
    role = load_settings().agent_role
    allowed = ROLE_TOOLS.get(role)
    if allowed is None:
        return True, role
    return (tool in allowed), role


def _ok(result) -> dict:
    return {"content": [{"type": "text", "text": result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, indent=2)}]}


def _err(msg: str) -> dict:
    return {"content": [{"type": "text", "text": f"Отказ: {msg}"}], "isError": True}


def tool_get_lab_status(_args: dict | None = None) -> dict:
    s = load_settings()
    return _ok(capabilities(s))


def tool_set_platform(args: dict) -> dict:
    s = load_settings()
    p = str(args.get("platform", "")).strip().lower()
    if p not in VALID_PLATFORMS:
        return _err(f"неизвестный профиль {p!r}. Разрешены: {', '.join(VALID_PLATFORMS)}")
    os.environ["LAB_PLATFORM"] = p
    state_path = write_runtime_state(lab_platform=p)
    s2 = load_settings()
    init_db(s2.database_url)
    log_event(s2.database_url, user="mcp", action="set_platform",
              detail=f"platform -> {p}; cidrs={s2.effective_cidrs}; state={state_path}")
    return _ok({"platform": p, "cidrs": s2.effective_cidrs, "persisted": state_path})


def tool_scan_lab_target(args: dict) -> dict:
    s = load_settings()
    init_db(s.database_url)
    target = str(args.get("target", "")).strip()
    if not target:
        return _err("пустая цель.")
    if looks_like_auth_attack_request(target):
        log_event(s.database_url, user="mcp", action="auth_action_denied", target=target[:200],
                  detail="auth-like mcp request refused")
        return _err(AUTH_REFUSAL_RU)
    if "," in target or any(c in target for c in (" ", "\n", "\t")) or (
            "/" in target and not target.lower().startswith(("http://", "https://"))):
        log_event(s.database_url, user="mcp", action="scan_denied", target=target[:200],
                  detail="multiple/subnet refused")
        return _err("одна цель на вызов. Списки, CIDR и подсети запрещены.")
    ok_rate, used = check_rate_limit(s.database_url, s.max_scans_per_hour)
    if not ok_rate:
        return _err(f"лимит {s.max_scans_per_hour} сканов/час исчерпан ({used}).")
    from .platforms import vpn_required_ok
    vpn_ok, vpn_msg = vpn_required_ok(s, target)
    if not vpn_ok:
        log_event(s.database_url, user="mcp", action="scan_denied", target=target[:200],
                  detail="vpn required but not detected")
        return _err(vpn_msg)
    verdict = check_target_allowed(target, s)
    if not verdict.allowed:
        log_event(s.database_url, user="mcp", action="scan_denied", target=target[:200],
                  detail=f"{verdict.reason}; {verdict.log_detail}")
        return _err(verdict.user_message or "цель не в lab-сети.")
    if verdict.kind == "offline":
        log_event(s.database_url, user="mcp", action="scan_denied", target=target[:200],
                  detail="offline ctf: no network scan")
        return _err("файловый CTF (offline) — сеть не сканируем. "
                    "init_session + get_ctf_playbook(reversing|crypto|forensics).")
    from .scanners import run_lab_scanners
    job = run_lab_scanners(target, s)
    if job.get("blocked"):
        log_event(s.database_url, user="mcp", action="scan_denied", target=target[:200],
                  detail=f"redirect denied; {job.get('blocked_detail', '')}")
        return _err(job["blocked"])
    findings = list(job.get("findings") or [])
    notes = list(job.get("notes") or [])
    dangers = [finding_danger(f) for f in findings]
    _base, _key, _model = resolve_endpoint(s)
    summary_md, origin = summarize(findings, "lab", llm_enabled=s.llm_enabled,
                                   base_url=_base, api_key=_key, model=_model)
    rep = write_report(reports_dir=os.path.join("data", "reports"), target_label=target[:120],
                       findings=findings, dangers=dangers, summary_md=summary_md,
                       summary_origin=origin, meta={"via": "mcp", "notes": notes})
    log_event(s.database_url, user="mcp", action="scan_ok", target=target[:200],
              scan_id=f"scan-{rep['scan_id']}", detail=f"{len(findings)} findings; {origin}")
    return _ok({"scan_id": f"scan-{rep['scan_id']}", "dir": rep["dir"],
                "findings": len(findings), "summary_origin": origin,
                "summary": summary_md[:3000], "notes": notes})


def tool_explain_mission(args: dict) -> dict:
    s = load_settings()
    init_db(s.database_url)
    text = str(args.get("text", ""))[:6000]
    if looks_like_auth_attack_request(text):
        log_event(s.database_url, user="mcp", action="auth_action_denied", target="explain_mission",
                  detail="auth-like mission text refused")
        return _err(AUTH_REFUSAL_RU)
    refused = refusal_for(text)
    if refused:
        log_event(s.database_url, user="mcp", action="explain_denied", target="explain_mission",
                  detail="refusal trigger")
        return _err(refused)
    if not llm_configured(s):
        log_event(s.database_url, user="mcp", action="explain_ok", target="explain_mission",
                  detail="local mission explain")
        return _ok("Локальный разбор (LLM выключен): разберите класс задачи на своей lab-VM — "
                   "что за уязвимость, чем опасна, какие базовые защиты. "
                   "Готовые флаги/шаги взлома не подсказываю; смотрите материалы комнаты и Web Fundamentals.")
    from .secrets import mask_secrets
    try:
        _base, _key, _model = resolve_endpoint(s)
        out = _chat_completion(_base, _key, _model,
                               "Объясни учебную миссию как преподаватель, без payload и шагов взлома. Текст миссии:\n"
                               + mask_secrets(text))
        log_event(s.database_url, user="mcp", action="explain_ok", target="explain_mission", detail="llm")
        return _ok(out)
    except Exception as e:
        return _ok(f"LLM недоступен ({type(e).__name__}). Разберите тему теоретически на своей lab-VM.")


def tool_explain_report(args: dict) -> dict:
    s = load_settings()
    init_db(s.database_url)
    findings = args.get("findings", [])
    if not isinstance(findings, list):
        return _err("findings должен быть списком.")
    findings = [f for f in findings if isinstance(f, dict)][:50]
    dangers = [finding_danger(f) for f in findings]
    _base, _key, _model = resolve_endpoint(s)
    summary_md, origin = summarize(findings, "imported_report", llm_enabled=s.llm_enabled,
                                   base_url=_base, api_key=_key, model=_model)
    log_event(s.database_url, user="mcp", action="explain_ok", target="inline_findings",
              detail=f"{len(findings)} findings; {origin}")
    return _ok({"summary_origin": origin, "summary": summary_md[:4000],
                "dangers": dangers[:20]})


def tool_import_scanbot_report(args: dict) -> dict:
    s = load_settings()
    init_db(s.database_url)
    path = str(args.get("path", "")).strip()
    try:
        report = load_scanbot_report(path)
    except (OSError, ValueError) as e:
        return _err(f"не могу прочитать JSON: {e}")
    findings = extract_findings(report)
    meta = report_meta(report, path)
    dangers = [finding_danger(f) for f in findings]
    _base, _key, _model = resolve_endpoint(s)
    summary_md, origin = summarize(findings, "imported_report", llm_enabled=s.llm_enabled,
                                   base_url=_base, api_key=_key, model=_model)
    rep = write_report(reports_dir=os.path.join("data", "reports"),
                       target_label=f"import:{meta.get('source_file','report')}",
                       findings=findings, dangers=dangers, summary_md=summary_md,
                       summary_origin=origin, meta={"via": "mcp", "imported_from": meta})
    log_event(s.database_url, user="mcp", action="explain_ok", target=meta.get("source_file","")[:200],
              scan_id=f"scan-{rep['scan_id']}", detail=f"import {len(findings)}; {origin}")
    return _ok({"scan_id": f"scan-{rep['scan_id']}", "findings": len(findings),
                "summary_origin": origin, "summary": summary_md[:3000]})


def tool_init_session(args: dict) -> dict:
    r = _init_session(str(args.get("machine", "")), str(args.get("target", "")))
    return _ok(r) if r.get("ok") else _err(str(r.get("error", "отказ")))


def tool_session_status(args: dict) -> dict:
    r = _session_status(str(args.get("machine", "")))
    return _ok(r) if r.get("ok") else _err(str(r.get("error", "отказ")))


def tool_log_note(args: dict) -> dict:
    r = _log_note(str(args.get("machine", "")), args.get("step", ""), str(args.get("text", "")))
    return _ok(r) if r.get("ok") else _err(str(r.get("error", "отказ")))


def tool_get_plan_step(args: dict) -> dict:
    r = _plan_step(args.get("step", ""), args.get("target"))
    return _ok(r) if r.get("ok") else _err(str(r.get("error", "отказ")))


def tool_read_session_file(args: dict) -> dict:
    r = _read_file(str(args.get("machine", "")), str(args.get("path", "")))
    if not r.get("ok"):
        return _err(str(r.get("error", "отказ")))
    if len(r.get("content", "")) > 6000:
        r = dict(r, content=r["content"][:6000] + "\n…[обрезано для чата, полный текст в файле]…")
    return _ok(r)


def tool_get_role_brief(args: dict) -> dict:
    r = _role_brief(args.get("role") if isinstance(args.get("role"), str) else None)
    return _ok(r)


def tool_harden_checklist(args: dict) -> dict:
    r = _harden(str(args.get("title", "")), str(args.get("description", "")))
    return _ok(r)


def tool_verify_fix(args: dict) -> dict:
    r = _verify_fix(str(args.get("target", "")), str(args.get("baseline", "")))
    return _ok(r) if r.get("ok") else _err(str(r.get("error", "отказ")))


def tool_get_ctf_playbook(args: dict) -> dict:
    cat = args.get("category")
    r = _ctf_playbook(cat if isinstance(cat, str) else None)
    return _ok(r)


TOOLS = {
    "get_lab_status": tool_get_lab_status,
    "set_platform": tool_set_platform,
    "scan_lab_target": tool_scan_lab_target,
    "explain_mission": tool_explain_mission,
    "explain_report": tool_explain_report,
    "import_scanbot_report": tool_import_scanbot_report,
    "init_session": tool_init_session,
    "session_status": tool_session_status,
    "log_note": tool_log_note,
    "get_plan_step": tool_get_plan_step,
    "read_session_file": tool_read_session_file,
    "get_role_brief": tool_get_role_brief,
    "harden_checklist": tool_harden_checklist,
    "verify_fix": tool_verify_fix,
    "get_ctf_playbook": tool_get_ctf_playbook,
}


def _dispatch_tool(name: str, args: dict) -> dict:
    if name in FORBIDDEN_TOOLS:
        s = load_settings()
        init_db(s.database_url)
        log_event(s.database_url, user="mcp", action="auth_action_denied" if "password" in name or "login" in name else "tool_denied",
                  target=name, detail="forbidden tool requested")
        return _err(f"tool {name!r} не существует в Lab Coach. " + AUTH_REFUSAL_RU if ("password" in name or "login" in name) else f"tool {name!r} запрещён этим ТЗ и не реализован.")
    fn = TOOLS.get(name)
    if not fn:
        return _err(f"неизвестный tool {name!r}. Разрешены: {', '.join(sorted(TOOLS))}")
    if name in ADMIN_TOOLS:
        try:
            require_admin_configured(load_settings())
        except SystemExit as e:
            return _err(str(e))
    ok, role = role_allowed(name)
    if not ok:
        s = load_settings()
        init_db(s.database_url)
        log_event(s.database_url, user=f"mcp:{role}", action="role_denied",
                  target=name, detail=f"[{role}] tool вне роли")
        return _err(f"tool {name!r} вне твоей роли ({role}). Твои tools — в tools/list.")
    try:
        return fn(args or {})
    except Exception as e:
        log.exception("tool %s failed", name)
        return _err(f"внутренняя ошибка ({type(e).__name__}).")


def serve_stdio() -> int:
    refuse_non_stdio()
    s = load_settings()
    init_db(s.database_url)
    stdin, stdout = sys.stdin, sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {}) or {}

        def reply(result=None, error=None):
            out = {"jsonrpc": "2.0", "id": mid}
            if error is not None:
                out["error"] = error
            else:
                out["result"] = result
            stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            stdout.flush()

        if method == "initialize":
            reply({"protocolVersion": "2024-11-05",
                   "serverInfo": {"name": "lab-coach", "version": __version__},
                   "capabilities": {"tools": {}}})
        elif method in ("notifications/initialized", "notifications/cancelled"):
            continue
        elif method == "tools/list":
            ok_role = load_settings().agent_role
            allowed = ROLE_TOOLS.get(ok_role)
            defs = TOOL_DEFS if allowed is None else [t for t in TOOL_DEFS if t["name"] in allowed]
            reply({"tools": defs, "role": ok_role})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            reply(_dispatch_tool(name, args))
        elif method == "ping":
            reply("pong")
        else:
            reply(None, {"code": -32601, "message": f"unknown method {method!r}"})
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        refuse_non_stdio()
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
