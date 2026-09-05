"""Coach-слой: сессии методологии plan.txt (шаги 0-6) на локальном HTB-каталоге.

Только файлы и текст: никакой сети к цели, никаких эксплойтов и входов.
Каждая сессия привязана к ОДНОЙ цели, проверенной LabPolicy при создании.
"""
from __future__ import annotations

import os
import re
import time

from .audit import init_db, log_event
from .policy import check_target_allowed, looks_like_auth_attack_request

SLUG_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SUBDIRS = ("nmap", "loot", "exploits", "www")
MAX_READ = 200_000

NOTES_TEMPLATE = """# Сессия: {machine} ({target})

- Scope: только {target}. Начало: {ts}
- Сеть: <host-only / tun0>

## 0. Подготовка



## 1. Recon



## 1.5 Lab Coach



## 2. Изучение



## 3. Foothold



## 4-5. Внутри



## 6. Финал
"""

STEP_GUIDES: dict[int, dict] = {
    0: {"title": "Подготовка",
        "body": ("Каркас: {subdirs} в каталоге сессии. Проверка связности: ping -c3 {target}. "
                 "Если у цели есть имя (planbox.htb, домен из разведки) — записать «IP имя» в /etc/hosts. "
                 "Открыть notes.md, зафиксировать scope и время старта.")},
    1: {"title": "Разведка (Recon)",
        "body": ("Сначала все порты, потом версии только найденных:\n"
                 "nmap -p- --min-rate 2000 -T4 {target} -oN nmap/allports.txt\n"
                 "nmap -p <PORTS> -sC -sV {target} -oN nmap/services.txt\n"
                 "Веб (если есть 80/443): ffuf vhost `Host: FUZZ.{domain}`, gobuster dir "
                 "(`-x php,txt,bak,zip`), robots.txt вручную. Каждый вывод — в свой файл, "
                 "выводы — в notes.md. Подсети не сканировать: только цель сессии.")},
    2: {"title": "Изучение сервисов и приложения",
        "body": ("Открыть веб глазами + исходник страницы, robots.txt, знакомые пути. "
                 "Определить стек и ТОЧНУЮ версию каждого сервиса. По каждому порту — соответствующий "
                 "раздел HackTricks, по приложению — searchsploit '<app> <version>'. "
                 "Найденные конфиги/бэкапы сложить в loot/ и разобрать построчно: креды, пути, TODO.")},
    3: {"title": "Точка входа (Foothold)",
        "body": ("Выбрать ОДИН наиболее вероятный вектор по итогам шагов 1-2 "
                 "(классы: слабый вход, LFI, загрузка файлов, инъекция, известный CVE, reuse кредов). "
                 "Работать аккуратно и по одному вектору за раз, каждый результат — в notes.md. "
                 "Получил доступ — сразу зафиксировать КАК (воспроизводимо) и забрать user.txt. "
                 "Lab Coach на этом этапе: только explain найденного класса, без готовых пейлоадов.")},
    4: {"title": "Энумерация изнутри",
        "body": ("Базовый набор: id, hostname, ip a, ls -la /, /.dockerenv, /etc/passwd, /home/*. "
                 "Дальше: sudo -l, SUID (`find / -perm -4000`), cron (`/etc/crontab`, `/etc/cron*`), "
                 "пароли/ключи в конфигах, history, ~/.ssh, reuse найденных ранее кредов. "
                 "Для полноты — linpeas/winPEAS из www/ своей атакующей. Всё интересное — в loot/.")},
    5: {"title": "Повышение привилегий",
        "body": ("Кандидаты по приоритету: sudo-правила (сверить с GTFOBins), SUID-бинари, "
                 "writable cron-скрипты и сервисы, креды из конфигов/history, побег из docker "
                 "при наличии /.dockerenv. Один вектор за раз, каждый шаг воспроизводимо в notes.md. "
                 "Цель шага — чтение root.txt, не «красивый рут-шелл».")},
    6: {"title": "Финал",
        "body": ("Собрать: user.txt, root.txt, путь foothold одной строкой, путь privesc одной строкой, "
                 "3 строки «чему научился». Привезти JSON Lab Coach-скана на explain. "
                 "Остановить машину/откатить снапшот, проверить, что notes.md полон.")},
}

# CTF docker: ping не отвечает, порт только из карточки, нет privesc-машины.
CTF_STEP_GUIDES: dict[int, dict] = {
    0: {"title": "Подготовка (CTF docker)",
        "body": ("Каркас сессии: {subdirs}. SPAWNED_TARGET = {target} (один инстанс). "
                 "Ping не делать: HTB docker на ping не отвечает. "
                 "Открыть в браузере http://{target}/ если web. Зафиксировать scope в notes.md.")},
    1: {"title": "Разведка (CTF)",
        "body": ("Только порт из карточки, не -p- и не подсеть. "
                 "Один gentle Lab Coach scan {target}. Заголовки/devtools, robots.txt. "
                 "Вложения таска — локально (zip площадки часто с паролем hackthebox).")},
    2: {"title": "Изучение исходника",
        "body": ("Читать выданный код: куда попадает ввод (время/format/filename). "
                 "Класс дыры — explain, без payload. Версии — только чтение advisory.")},
    3: {"title": "Проверка гипотезы",
        "body": ("Один аккуратный вектор руками, результат в notes. "
                 "Флаг не добывает агент — человек сдаёт HTB{{…}} на площадке.")},
    4: {"title": "Заметки / loot",
        "body": ("Выводы в loot/, флаг только в loot/flags.txt сессии. Не в git и не в чужой чат.")},
    5: {"title": "Защита (blue)",
        "body": ("harden_checklist по классу: allowlist, без shell, обновления. Не атака.")},
    6: {"title": "Финал",
        "body": ("Сдать флаг на сайте, Terminate docker, очистить SPAWNED_TARGET, "
                 "3 строки «чему научился» в notes.md.")},
}


def htb_root() -> str:
    from .config import load_settings
    return os.path.expanduser((load_settings().htb_dir or "~/HTB"))


def machine_dir(machine: str) -> str:
    m = (machine or "").strip()
    if not SLUG_RX.match(m):
        raise ValueError(f"плохое имя сессии {m!r}: только латиница/цифры/._- до 64 символов")
    root = os.path.abspath(htb_root())
    d = os.path.abspath(os.path.join(root, m))
    if d != root and not d.startswith(root + os.sep):
        raise ValueError("выход за пределы HTB-каталога запрещён")
    return d


def scope_target(machine: str) -> str:
    try:
        with open(os.path.join(machine_dir(machine), "scope.txt"), encoding="utf-8") as f:
            return f.read().strip().splitlines()[0] if f else ""
    except OSError:
        return ""


def init_session(machine: str, target: str) -> dict:
    from .config import load_settings
    s = load_settings()
    init_db(s.database_url)
    target = (target or "").strip()
    verdict = check_target_allowed(target, s)
    if not verdict.allowed:
        log_event(s.database_url, user=f"mcp:{s.agent_role}", action="session_denied", target=target[:200],
                  detail=f"[{s.agent_role}] {verdict.reason}; {verdict.log_detail}")
        return {"ok": False, "error": verdict.user_message or "цель не в lab-сети."}
    try:
        d = machine_dir(machine)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    for sub in SUBDIRS:
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    with open(os.path.join(d, "scope.txt"), "w", encoding="utf-8") as f:
        f.write(f"SCOPE: только {target} (сессия {machine.strip()}).\nПодсети, чужие IP, интернет — запрещены.\n")
    notes = os.path.join(d, "notes.md")
    if not os.path.exists(notes):
        ts = time.strftime("%Y-%m-%d %H:%M")
        with open(notes, "w", encoding="utf-8") as f:
            f.write(NOTES_TEMPLATE.format(machine=machine.strip(), target=target, ts=ts))
    log_event(s.database_url, user=f"mcp:{s.agent_role}", action="session_init", target=target[:200],
              detail=f"[{s.agent_role}] session {machine.strip()}")
    ctf = s.lab_platform == "ctf" or bool(s.spawned_target)
    hint = ("Дальше: get_plan_step(0). CTF docker: не ping, браузер http://цель/ и исходники."
            if ctf else
            "Дальше: get_plan_step(0), затем ping и /etc/hosts.")
    return {"ok": True, "dir": d, "target": target,
            "subdirs": list(SUBDIRS),
            "hint": hint}


def _notes_stage_done(notes: str, markers: tuple[str, ...]) -> bool:
    low = notes.lower()
    return any(m.lower() in low for m in markers)


def session_status(machine: str) -> dict:
    try:
        d = machine_dir(machine)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not os.path.isdir(d):
        return {"ok": False, "error": f"сессии {machine!r} нет — сначала init_session."}
    files: list[str] = []
    for root, _ds, fs in os.walk(d):
        for fn in sorted(fs):
            rel = os.path.relpath(os.path.join(root, fn), d)
            if len(files) < 100:
                files.append(rel)
    try:
        with open(os.path.join(d, "notes.md"), encoding="utf-8") as f:
            notes = f.read()
    except OSError:
        notes = ""
    stages = {
        # Маркеры — только следы реальной работы (заголовки пустого шаблона не считаются).
        "0 подготовка": True,  # сессия создана = шаг 0 начат
        "1 recon": os.path.exists(os.path.join(d, "nmap", "allports.txt")),
        "1.5 coach": _notes_stage_done(notes, ("scan-",)),
        "2 изучение": _notes_stage_done(notes, ("стек", "версия", "searchsploit")),
        "3 foothold": _notes_stage_done(notes, ("user.txt", "PLANBOX{")),
        "4-5 внутри/privesc": _notes_stage_done(notes, ("root.txt", "privesc", "sudo -l")),
        "6 финал": _notes_stage_done(notes, ("чему научился",)),
    }
    order = ["0 подготовка", "1 recon", "1.5 coach", "2 изучение",
             "3 foothold", "4-5 внутри/privesc", "6 финал"]
    nxt = next((k for k in order if not stages[k]), "6 финал")
    return {"ok": True, "machine": machine.strip(), "scope": scope_target(machine),
            "files": files, "stages": stages, "next": nxt,
            "hint": f"Следующий шаг: {nxt} (подробности — get_plan_step)."}


def log_note(machine: str, step: int | str, text: str) -> dict:
    from .config import load_settings
    s = load_settings()
    init_db(s.database_url)
    try:
        step_n = int(str(step).strip())
    except (ValueError, AttributeError):
        return {"ok": False, "error": "step должен быть числом 0-6."}
    if step_n not in STEP_GUIDES:
        return {"ok": False, "error": "step должен быть 0-6."}
    body = (text or "").strip()
    if not body or len(body) > 4000:
        return {"ok": False, "error": "текст заметки: 1-4000 символов."}
    try:
        d = machine_dir(machine)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not os.path.isdir(d):
        return {"ok": False, "error": f"сессии {machine!r} нет — сначала init_session."}
    ts = time.strftime("%Y-%m-%d %H:%M")
    with open(os.path.join(d, "notes.md"), "a", encoding="utf-8") as f:
        f.write(f"\n### Заметка (шаг {step_n}, {ts}):\n{body}\n")
    log_event(s.database_url, user=f"mcp:{s.agent_role}", action="session_note",
              target=machine.strip()[:200], detail=f"[{s.agent_role}] step {step_n}, {len(body)} chars")
    out: dict = {"ok": True, "machine": machine.strip(), "step": step_n}
    if looks_like_auth_attack_request(body):
        out["reminder"] = ("Напоминание: Lab Coach не выполняет входы и не меняет пароли "
                           "(здесь только текст заметки, действий не выполняется).")
    return out


def get_plan_step(step: int | str, target: str | None = None) -> dict:
    try:
        step_n = int(str(step).strip())
    except (ValueError, AttributeError):
        return {"ok": False, "error": "step должен быть числом 0-6."}
    from .config import load_settings
    s = load_settings()
    guides = CTF_STEP_GUIDES if (s.lab_platform == "ctf" or bool(s.spawned_target)) else STEP_GUIDES
    guide = guides.get(step_n)
    if not guide:
        return {"ok": False, "error": "step должен быть 0-6."}
    t = (target or "").strip()
    warn = ""
    if t:
        v = check_target_allowed(t, s)
        if not v.allowed:
            warn = ("Цель не прошла LabPolicy — в командах оставлен плейсхолдер <IP>. "
                    f"Причина: {v.user_message}")
            t = ""
    ip = t or "<IP>"
    domain = "planbox.htb" if (t in ("192.168.56.110",) or not t) else "<DOMAIN>"
    body = guide["body"].format(target=ip, domain=domain,
                                subdirs="{nmap,loot,exploits,www}")
    if warn:
        body = warn + "\n\n" + body
    return {"ok": True, "step": step_n, "title": guide["title"], "guide": body}


# ---------- Blue: защита ----------

# класс -> (ключи, чек-лист закрытия, как проверить)
DEFENSE_KB: list[tuple[tuple[str, ...], str, list[str], str]] = [
    (("sqli", "sql injection", "sql-инъекц"), "SQL-инъекция",
     ["Prepared statements / ORM вместо конкатенации SQL",
      "Минимальные права у DB-пользователя сайта (без DROP/FILE/GRANT)",
      "Скрыть тексты ошибок БД от посетителя (общая страница ошибки + лог)",
      "Обновить СУБД и драйвер"],
     "Повторный поиск параметров в коде + verify_fix по скану."),
    (("xss", "cross-site", "межсайт"), "XSS",
     ["Экранирование по контексту (HTML/атрибут/JS/URL)",
      "Content-Security-Policy, HttpOnly + SameSite на cookie",
      "Модерация/фильтр пользовательского контента, капча на формах"],
     "Проверить заголовки ответа и флаги cookie в devtools."),
    (("csrf",), "CSRF",
     ["CSRF-токен на все меняющие действия", "SameSite=Lax/Strict",
      "Проверка Origin/Referer на критичных формах", "Никаких изменений по GET"],
     "Повторить действие без токена — должен быть отказ."),
    (("ssrf",), "SSRF",
     ["Allowlist назначений", "Запрет 169.254.169.254 и внутренних диапазонов",
      "Egress-фильтр и таймауты исходящих запросов"],
     "Подсунуть URL на metadata/внутренний хост в тестовой среде — отказ."),
    (("lfi", "rfi", "path traversal", "traversal"), "LFI/Traversal",
     ["Allowlist имён вместо путей", "basename/нормализация + корень-jail",
      "Файлы вне webroot", "allow_url_include=Off"],
     "Запросить ../.. и абсолютные пути — отказ/нормализация."),
    (("upload", "загрузк"), "Загрузка файлов",
     ["Allowlist типов + перекодирование изображений", "Случайные имена файлов",
      "Хранение вне webroot", "NoExec на каталоге загрузок"],
     "Загрузить тестовый набор (php/txt/двойное расширение) — отклонены."),
    (("xxe", "xml external", "внешние сущности"), "XXE",
     ["Запретить external entities и DTD, где не нужны", "Обновить XML-парсер",
      "Валидация схемы до разбора"],
     "Скормить тестовый XML с сущностью — сущность не резолвится."),
    (("ssti", "template injection", "инъекция шаблонов"), "SSTI",
     ["Не собирать шаблоны из пользовательского ввода", "Sandbox/allowlist движка", "Обновления"],
     "Ввести маркер шаблона в каждое поле — рендерится как текст."),
    (("deserial", "десериализац", "unserialize", "pickle"), "Десериализация",
     ["Не десериализовать недоверенное", "JSON/подписанные токены вместо объектов", "Обновить библиотеки"],
     "Ревью мест unserialize/pickle в коде — их не должно остаться."),
    (("idor", "прям", "broken access", "доступ к чуж"), "IDOR/доступ",
     ["Проверка владельца КАЖДОГО объекта на сервере", "Неперечислимые id (UUID)",
      "Тесты матрицы «роль × объект»"],
     "Открыть чужой id без прав — 403, без различия с 404 по смыслу."),
    (("default login", "default credential", "weak password", "слабый пароль", "дефолтн"), "Слабые креды",
     ["Уникальный длинный пароль", "2FA", "Нестандартный URL админки", "Лишние учётки удалить"],
     "Вход только со сложным паролем + 2FA; лишних учёток нет."),
    (("brute", "перебор парол", "credential stuffing"), "Перебор",
     ["Rate limit + временная блокировка", "Капча после N попыток",
      "Алерты о входах", "2FA"],
     "N неверных входов подряд → блокировка/задержка + алерт."),
    (("jwt", "session fixation", "фиксация сессии", "угон сессии"), "Сессии/токены",
     ["Rotation id после входа", "HttpOnly/Secure/SameSite", "Короткие TTL + инвалидация на выходе"],
     "Токен до входа не работает после, флаги cookie на месте."),
    (("auth bypass", "обход авторизации", "обход аутентификации", "без пароля"), "Обход авторизации",
     ["Единая точка проверки прав", "Deny-by-default", "Ревью условий доступа", "Тесты на обход"],
     "Прямые URL закрытых разделов без сессии — отказ."),
    ((" outdated", "version", "eol", "устаревш", "cve-"), "Устаревшее ПО/CVE",
     ["Инвентарь версий", "Обновление с бэкапом", "Подписка на бюллетени CMS"],
     "verify_fix: находка исчезла из повторного скана."),
    (("ssl", "tls", "certificate", "сертификат", "hsts"), "TLS",
     ["TLS 1.2+", "HSTS", "Автопродление сертификата", "http→https редирект"],
     "Проверка протокола и цепочки в браузере/панели."),
    (("header", "заголовок", "csp", "clickjacking", "x-frame"), "Заголовки",
     ["CSP", "X-Frame-Options/frame-ancestors", "Referrer-Policy", "X-Content-Type-Options"],
     "Заголовки видны в ответе сервера."),
    (("command injection", "os command", "cmd injection", "date format"), "Инъекция в команду ОС",
     ["Не склеивать ввод с shell", "Allowlist формата даты/аргументов", "escapeshellarg / argv без shell",
      "Минимальные права процесса"],
     "В lab: пользовательский формат не уходит в date(1)/system()."),
]

GENERIC_DEFENSE = (["Определить класс находки", "Закрыть по документации вендора/CMS",
                    "Бэкап до изменений", "Проверить повторным сканом (verify_fix)"],
                   "Находка исчезла из повторного скана.")


def harden_checklist(title: str, description: str = "") -> dict:
    from .explain import _key_hit
    t = f"{title or ''} {description or ''}".lower()
    for keys, name, items, verify in DEFENSE_KB:
        if any(_key_hit(t, k) for k in keys):
            return {"ok": True, "class": name, "checklist": items, "verify_how": verify}
    items, verify = GENERIC_DEFENSE
    return {"ok": True, "class": "Общая находка", "checklist": items, "verify_how": verify}


def verify_fix(target: str, baseline: str) -> dict:
    """Синий цикл: повторный скан СВОЕЙ lab-цели + сравнение с baseline-отчётом."""
    from .config import load_settings
    from .importer import extract_findings, load_scanbot_report
    from .policy import normalize_scan_target
    from .ratelimit import check_rate_limit
    from .scanners import run_nuclei
    s = load_settings()
    init_db(s.database_url)
    role = s.agent_role
    try:
        base_report = load_scanbot_report((baseline or "").strip())
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"не могу прочитать baseline JSON: {e}"}
    base = {(f.get("title", ""), f.get("severity", "")) for f in extract_findings(base_report)}
    target = (target or "").strip()
    verdict = check_target_allowed(target, s)
    if not verdict.allowed:
        log_event(s.database_url, user=f"mcp:{role}", action="scan_denied",
                  target=target[:200], detail=f"[{role}] verify {verdict.reason}; {verdict.log_detail}")
        return {"ok": False, "error": verdict.user_message or "цель не в lab-сети."}
    ok_rate, used = check_rate_limit(s.database_url, s.max_scans_per_hour)
    if not ok_rate:
        return {"ok": False, "error": f"лимит {s.max_scans_per_hour} сканов/час исчерпан ({used})."}
    nuc = run_nuclei(target, s.nuclei_path, s.scan_timeout_seconds)
    now = {(f.get("title", ""), f.get("severity", "")) for f in nuc.get("findings", [])}
    fixed = sorted(t for t in base - now)
    persisting = sorted(t for t in base & now)
    new = sorted(t for t in now - base)
    reliable = nuc.get("status") == "ok"
    verdict_lines = [f"Исправлено: {len(fixed)}; осталось: {len(persisting)}; новое: {len(new)}."]
    if not reliable:
        verdict_lines.append("Сканер недоступен/упал — сравнение условно, сначала почини запуск Nuclei.")
    for t, sev in fixed[:10]:
        verdict_lines.append(f"  [+] {t} [{sev}]")
    for t, sev in persisting[:10]:
        verdict_lines.append(f"  [=] {t} [{sev}]")
    for t, sev in new[:10]:
        verdict_lines.append(f"  [!] {t} [{sev}]")
    log_event(s.database_url, user=f"mcp:{role}", action="verify_ok", target=target[:200],
              detail=f"[{role}] fixed={len(fixed)} persist={len(persisting)} new={len(new)} reliable={reliable}")
    return {"ok": True, "target": target, "fixed": fixed, "persisting": persisting,
            "new": new, "reliable": reliable,
            "notes": [nuc.get("note", "")] if nuc.get("note") else [],
            "verdict": "\n".join(verdict_lines)}


# ---------- CTF-арена ----------

CTF_RULES = (
    "Правила HTB CTF: не атаковать инфраструктуру платформы и другие команды, "
    "не брутить форму сдачи флагов, не делиться флагами/райтапами с другими командами, "
    "никакого DDoS и агрессивных многопоточных сканов, одна команда на ивент. "
    "Флаги живут только в loot/flags.txt сессии и сдаются человеком на платформе."
)

CTF_PLAYBOOKS: dict[str, dict] = {
    "web": {"title": "Web",
            "body": ("Инстанс: IP:port из карточки → SPAWNED_TARGET (один на сессию). "
                     "Триаж: заголовки и devtools, robots.txt/sitemap, исходники если приложены, "
                     "аккуратный dir-перебор маленьким словарём, версии → searchsploit (только чтение). "
                     "Один gentle-скан Nuclei на инстанс, не флудить. Флаг — в loot/flags.txt, сдаёт человек.")},
    "pwn": {"title": "Pwn",
            "body": ("Скачай бинарь/исходники, всё — локально: file, checksec, чтение исходников, "
                     "прогон у себя. Сетевой инстанс трогаем только точечными проверками по заданию, "
                     "без флуда и брута. Эксплойт под конкретный бинарь пишешь сам — coach разбирает классы.")},
    "crypto": {"title": "Crypto",
            "body": ("Собери выданное (шифртекст, параметры, исходник). Определи схему, вспомни классические "
                     "слабости класса. Солвер пишешь и крутишь ЛОКАЛЬНО на выданных данных. "
                     "Ораклы на инстансе дёргать точечно, не перебором.")},
    "forensics": {"title": "Forensics",
            "body": ("Всё локально на копиях: file/strings/headers, exif, wireshark/tshark (только чтение), "
                     "entropy и сигнатуры, steg-инструменты на копиях. Оригиналы не портить, выводы — в loot/.")},
    "reversing": {"title": "Reversing",
            "body": ("file + strings, затем декомпилятор (ghidra и аналоги). Чужой бинарь НЕ запускать на хосте — "
                     "только изолированная VM/снапшот. Ключи/флаги искать в логике, не запуском вслепую.")},
    "misc": {"title": "Misc",
            "body": ("Внимательно перечитать текст задания (часто подсказка внутри). Проверить кодировки "
                     "(base64/hex), реальный тип файла vs расширение, скрытые слои/комментарии.")},
    "osint": {"title": "OSINT",
            "body": ("Только пассивное чтение публичных источников. Не контактировать с реальными людьми "
                     "и системами от имени задания, не нарушать приватность. Фиксировать цепочку выводов.")},
    "blockchain": {"title": "Blockchain",
            "body": ("Работать только с RPC/сетью из карточки задания. Локальный форк/тестнет для отладки. "
                     "Приватные ключи задания — только в loot/, никуда не публиковать.")},
    "warmup": {"title": "Warmup",
               "body": ("Try Out / ивент 1434: сначала описание и вложения, не brute. "
                        "Если есть Spawn — SPAWNED_TARGET=IP:port, ping не ждать. "
                        "Web-UI открыть в браузере. Zip: пароль площадки hackthebox. "
                        "Один gentle-скан, класс дыры через explain, флаг сдаёт человек.")},
}
CTF_ALIASES = {"forensic": "forensics", "rev": "reversing",
               "reverse": "reversing", "pwnable": "pwn", "webapp": "web",
               "steg": "forensics", "stego": "forensics",
               "warm-up": "warmup", "warm": "warmup"}


def get_ctf_playbook(category: str | None = None) -> dict:
    c = (category or "").strip().lower()
    key = CTF_ALIASES.get(c, c)
    if key in CTF_PLAYBOOKS:
        p = CTF_PLAYBOOKS[key]
        return {"ok": True, "category": p["title"], "playbook": p["body"], "rules": CTF_RULES}
    known = sorted(p["title"] for p in CTF_PLAYBOOKS.values())
    generic = ("Триаж: перечитать задание, классифицировать (файл/сеть/крипто/текст), "
               "инвентарь выданного, самая маленькая проверка первой. "
               "Флаг — в loot/flags.txt, сдаёт человек.")
    return {"ok": True, "category": "Generic", "playbook": generic,
            "known": known, "rules": CTF_RULES}


# ---------- Роли ----------

RED_BRIEF = (
    "Ты — RED-агент (атакующий) учебных учений на изолированном полигоне. "
    "Твоя работа: вести человека по методологии plan.txt 0–6 через tools: init_session (scope на ОДНУ lab-цель), "
    "get_plan_step (что делать), scan_lab_target (только цель сессии), explain_report (разбор классов), "
    "log_note/session_status/read_session_file (память сессии). "
    "Правила: команды выполняет ЧЕЛОВЕК, ты планируешь и фиксируешь. Одна сессия — одна цель. "
    "Подсети, чужие IP, интернет — запрещены. Тебе НЕЛЬЗЯ: выдавать payload/эксплойты/shellcode/reverse shell, "
    "помогать входить без пароля, менять пароли, давать готовые шаги взлома конкретной машины — только классы, "
    "чек-листы и вопросы. Защитными tools (harden_checklist, verify_fix) ты не владеешь — это работа синего."
)

BLUE_BRIEF = (
    "Ты — BLUE-агент (защитник) учебных учений. Твоя работа: по находкам строить защиту через harden_checklist "
    "(чек-лист закрытия + как проверить), принимать отчёты через explain_report, мерить прогресс через verify_fix "
    "(повторный скан СВОЕЙ lab-цели vs baseline). Сессия общая с красным: читай session_status/read_session_file, "
    "чтобы знать, что он нашёл, и закрывай это. Заметки подписывай [blue] через log_note. "
    "Правила: защищаешь только свои lab-системы; сканы — только verify_fix по цели сессии; "
    "атакующими tools (get_plan_step, scan_lab_target) ты не владеешь. "
    "Входы/пароли/пейлоады — вне объёма для обеих сторон."
)

COACH_BRIEF = (
    "Ты — COACH: полный доступ ко всем tools. Веди учение: красному — методологию, синему — защиту, "
    "следи за scope (одна цель на сессию) и фиксируй всё в notes. Запреты обеих сторон действуют и для тебя."
)

BRIEFS = {"red": RED_BRIEF, "blue": BLUE_BRIEF, "coach": COACH_BRIEF}


def get_role_brief(role: str | None = None) -> dict:
    from .config import load_settings
    r = (role or "").strip().lower() or load_settings().agent_role
    if r not in BRIEFS:
        r = "coach"
    return {"ok": True, "role": r, "brief": BRIEFS[r]}


def read_session_file(machine: str, path: str) -> dict:
    try:
        d = machine_dir(machine)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    p = (path or "").strip().lstrip("/")
    if not p or p in (".",):
        return {"ok": False, "error": "пустой путь."}
    norm = os.path.normpath(p)
    if norm.startswith("..") or os.path.isabs(norm):
        return {"ok": False, "error": "выход за пределы сессии запрещён."}
    full = os.path.abspath(os.path.join(d, norm))
    if full != d and not full.startswith(d + os.sep):
        return {"ok": False, "error": "выход за пределы сессии запрещён."}
    try:
        size = os.path.getsize(full)
        with open(full, encoding="utf-8", errors="replace") as f:
            content = f.read(MAX_READ + 1)
    except OSError as e:
        return {"ok": False, "error": f"не могу прочитать: {e.strerror or e}"}
    truncated = len(content) > MAX_READ
    return {"ok": True, "path": norm, "size": size,
            "truncated": truncated, "content": content[:MAX_READ]}
