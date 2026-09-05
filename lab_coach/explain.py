"""Локальные шаблоны «Чем опасно» + OpenRouter-саммари (F-LLM-03/04/05)."""
from __future__ import annotations

import json
import re

from .llm import chat_completion
from .secrets import mask_obj

# Локальная база знаний по классам (без эксплойтов, только смысл + учёба).
LOCAL_KB: list[tuple[tuple[str, ...], str, str]] = [
    (("xss", "cross-site", "межсайт"), "XSS",
     "Скрипт в чужой странице может действовать от имени посетителя. В lab: разберите типы (reflected/stored/DOM), "
     "контексты экранирования и CSP. Почитать: комнаты THM по XSS / Web Fundamentals."),
    (("sqli", "sql injection", "sql-инъекц"), "SQL-инъекция",
     "Нарушение разделения кода и данных в запросах к БД. В lab: разберите параметризованные запросы и ORM, "
     "посмотрите, как ошибка меняет логику запроса — без утаскивания данных. Почитать: THM SQLi."),
    (("default login", "default credential", "weak password", "слабый пароль", "дефолтн"), "Слабый/дефолтный вход",
     "Типовые учётки — частая причина компрометации стендов. Ничего не «проверяем входом»: смените пароли штатно "
     "в админке/панели, включите 2FA. В lab поднимите свою VM и отработайте политику паролей."),
    (("auth bypass", "обход авторизации", "обход аутентификации", "без пароля"), "Обход авторизации",
     "Дефект проверки прав: пользователь видит/чужое или входит без проверки. ВХОД НЕ ВОСПРОИЗВОДИМ даже в lab-цели "
     "через этот инструмент. Разбирайте теорию: сессии, JWT, IDOR, матрицы доступа. Свой пароль — только штатно."),
    (("rce", "remote code", "удалённое выполнение"), "RCE",
     "Выполнение чужого кода на сервере — критично. Эксплойты НЕ запускаем и НЕ генерируем. "
     "В lab: учитесь по обновлениям версий, принципу наименьших привилегий и изоляции сервисов."),
    (("lfi", "rfi", "path traversal", "directory traversal", "traversal"), "LFI/Path Traversal",
     "Чтение файлов за пределами web-корня. В lab: разберите нормализацию путей, chroot/jail, allowlist. "
     "Чужие файлы не читаем."),
    (("ssrf",), "SSRF",
     "Сервер просят сходить по чужому URL. В lab: allowlist назначений, запрет metadata (169.254.169.254), egress-фильтры."),
    (("csrf",), "CSRF",
     "Действие от имени жертвы через её браузер. В lab: SameSite, CSRF-токены, проверка Origin."),
    (("open redirect", "открытый редирект"), "Open Redirect",
     "Доверие к параметру next/url. В lab: allowlist адресов, относительные пути."),
    ((" outdated", "version", "eol", "устаревш"), "Устаревшее ПО",
     "Старые версии копят известные дыры. В lab: инвентаризация версий, обновления, сравнение с fix-релизами."),
    (("ssl", "tls", "certificate", "сертификат", "hsts"), "TLS/SSL",
     "Слабый шифр/сертификат снижает доверие к соединению. В lab: разберите handshake, HSTS, проверку цепочки."),
    (("header", "заголовок", "csp", "clickjacking", "x-frame"), "HTTP-заголовки",
     "Отсутствие защитных заголовков упрощает XSS/clickjacking. В lab: CSP, X-Frame-Options, Referrer-Policy."),
    (("cve-",), "CVE",
     "Публичный идентификатор уязвимости. Разберите описание и affected versions, обновите lab-стенд до fix-версии."),
    (("xxe", "xml external", "внешние сущности"), "XXE",
     "XML-парсер ходит за внешними сущностями/файлами. В lab: разберите, как парсер резолвит сущности. "
     "Защита: запретить external entities и DTD там, где они не нужны; обновить парсер."),
    (("ssti", "template injection", "инъекция шаблонов"), "SSTI",
     "Пользовательский ввод попадает в шаблонизатор и выполняется как код шаблона. "
     "Защита: никогда не собирать шаблоны из пользовательского ввода, sandbox/allowlist, обновления движка."),
    (("idor", "прям", "broken access", "доступ к чуж"), "IDOR / слабый контроль доступа",
     "Объект запрашивается по предсказуемому id без проверки владельца. ВХОДЫ И ПЕРЕБОР ЧУЖИХ ID НЕ ВЫПОЛНЯЕМ. "
     "Разбирайте теорию прав доступа. Защита: проверка владельца каждого объекта на сервере, неперечислимые id, тесты матрицы прав."),
    (("upload", "загрузк файлов"), "Опасная загрузка файлов",
     "Файл от пользователя оказывается исполняемым/доступным на сервере. "
     "Защита: allowlist типов, перекодирование изображений, случайные имена, хранение вне webroot, запрет исполнения в каталоге загрузок."),
    (("brute", "перебор парол", "credential stuffing", "подбор учёт"), "Перебор учётных данных",
     "Автоподбор паролей по словарям/утечкам. АТАК НЕ ПРОВОДИМ даже в lab-целях этим инструментом. "
     "Защита: длинные уникальные пароли, 2FA, rate limit и временная блокировка, мониторинг входов, оповещения."),
    (("deserial", "десериализац", "unserialize", "pickle"), "Небезопасная десериализация",
     "Доверяем структуре данных от клиента — она выполняется при разборе. "
     "Защита: не десериализовать недоверенное, использовать JSON/подписанные токены, обновления библиотек."),
    (("jwt", "session fixation", "фиксация сессии", "угон сессии"), "Сессии и токены",
     "Слабые/вечные токены, фиксация сессии, отсутствие привязок. СЕССИИ НЕ ПОДМЕНЯЕМ. "
     "Защита: длинные случайные id, rotation после входа, HttpOnly/Secure/SameSite, короткие TTL, инвалидация на выходе."),
]


def _key_hit(haystack: str, key: str) -> bool:
    # Короткие ключи (rce, xss, lfi...) — только целым словом, иначе «force» даёт ложное RCE.
    if len(key) <= 4:
        return re.search(r"\b" + re.escape(key) + r"\b", haystack) is not None
    return key in haystack


def local_danger(title: str, description: str = "") -> str:
    t = f"{title or ''} {description or ''}".lower()
    for keys, name, text in LOCAL_KB:
        if any(_key_hit(t, k) for k in keys):
            return f"{name}. {text}"
    return ("Общая находка сканера. Разберите класс проблемы на своей lab-VM: что это, "
            "чем опасно в изолированной сети и как закрывается (обновление/конфиг/доступ). "
            "Эксплойты и входы на цели не используем.")


def finding_danger(f: dict) -> str:
    base = local_danger(str(f.get("title", "")), str(f.get("description", "")))
    # Спец-случай: auth bypass / default login в импортированном отчёте —
    # только объяснить + штатный сброс, без шагов входа (приёмка §15).
    low = f"{f.get('title','')} {f.get('description','')}".lower()
    if any(k in low for k in ("auth bypass", "обход авторизации", "default login", "без пароля")):
        base += (" Важно: вход через уязвимость не воспроизводим. "
                 "Смените пароль штатно (админка CMS / панель хостинга / phpMyAdmin владельца).")
    return base


REFUSAL_TRIGGERS = (
    "poc", "proof of concept", "reverse shell", "войти без пароля", "вход без пароля",
    "сменить пароль на", "обход", "payload", "shellcode", "metasploit",
)


def refusal_for(prompt_text: str) -> str | None:
    low = (prompt_text or "").lower()
    if any(k in low for k in REFUSAL_TRIGGERS):
        return ("Отказ: Lab Coach не пишет PoC/payload/reverse shell и не помогает входить "
                "без пароля или менять пароль на цели. Могу объяснить теорию класса уязвимости "
                "и подсказать, что почитать для lab.")
    return None


def summarize(findings: list[dict], target_kind: str, *, llm_enabled: bool,
              base_url: str, api_key: str, model: str) -> tuple[str, str]:
    """Возвращает (summary_md, origin), origin ∈ {llm, local, llm_unavailable, refused}."""
    safe = mask_obj({"findings": findings, "target_kind": target_kind})
    if not llm_enabled or not api_key:
        lines = ["### Учебное саммари (локально, без LLM)", ""]
        for f in findings[:20]:
            lines.append(f"- **{f.get('title','(без названия)')}** [{f.get('severity','info')}] — {finding_danger(f)}")
        if not findings:
            lines.append("Находок нет. Проверьте охват скана и повторите на lab-цели.")
        return "\n".join(lines) + "\n", "local"
    try:
        payload = json.dumps(safe, ensure_ascii=False)[:12000]
        text = chat_completion(base_url, api_key, model,
                               f"Разбери находки lab-сканера простым языком. JSON:\n{payload}")
        if not text.strip():
            raise RuntimeError("empty llm response")
        return text.strip() + "\n", "llm"
    except Exception as e:
        lines = ["### Учебное саммари (LLM недоступен — локальный разбор)", ""]
        for f in findings[:20]:
            lines.append(f"- **{f.get('title','(без названия)')}** [{f.get('severity','info')}] — {finding_danger(f)}")
        lines.append("")
        lines.append(f"_Заметка: LLM недоступен ({type(e).__name__}). Отчёт записан с локальным explain._")
        return "\n".join(lines) + "\n", "llm_unavailable"
