"""Категорийные шаги и опциональные soft-hints (без payload)."""
from __future__ import annotations

from .explain import _key_hit

CATEGORIES = (
    "web", "pwn", "reversing", "crypto", "forensics", "misc",
    "osint", "blockchain", "warmup", "machine",
)

# Явные шаги человеку. Без команд атаки и без готовых строк.
CATEGORY_STEPS: dict[str, dict] = {
    "web": {
        "you_run": [
            "Заголовки ответа, cookies, robots.txt, исходник страницы",
            "Список форм и параметров: куда уходит ввод (query/body/file/header)",
            "Точная версия стека — advisory читать, PoC не копировать",
        ],
        "questions": [
            "Какой один класс самый вероятный (XSS, SQLi, LFI, cmd, SSTI, upload)?",
            "Есть ли скрытый раздел (admin) за флагом/режимом, а не «просто URL»?",
        ],
    },
    "pwn": {
        "you_run": [
            "Скачать бинарь/исходник, работать ЛОКАЛЬНО: file, checksec, чтение кода",
            "Сетевой инстанс — только точечная проверка гипотезы, без флуда",
        ],
        "questions": [
            "Где копирование/чтение без границы?",
            "Какие защиты включены (NX, PIE, canary) — это сужает класс, не даёт эксплойт",
        ],
    },
    "reversing": {
        "you_run": [
            "file + strings на копии; декомпилятор только в изолированной VM",
            "Искать ключ/флаг в логике, не запуском вслепую на хосте",
        ],
        "questions": ["Какая функция принимает ввод?", "Есть ли проверка лицензии/формата?"],
    },
    "crypto": {
        "you_run": [
            "Собрать шифртекст, параметры, исходник в loot/",
            "Солвер писать и крутить локально на выданных данных",
        ],
        "questions": ["Какая схема (xor, RSA, AES-ECB…)?", "Где повтор ключа / слабый padding / leak?"],
    },
    "forensics": {
        "you_run": [
            "Копии, не оригинал: file/strings/headers, exif, tshark только чтение",
            "Фиксировать цепочку выводов в notes.md",
        ],
        "questions": ["Реальный тип файла vs расширение?", "Где спрятан второй слой?"],
    },
    "misc": {
        "you_run": ["Перечитать текст задания целиком", "Кодировки (base64/hex), комментарии, скрытые слои"],
        "questions": ["Что автор написал между строк?"],
    },
    "osint": {
        "you_run": ["Только пассивные публичные источники", "Не писать живым людям от имени задания"],
        "questions": ["Какая цепочка фактов, а не догадка?"],
    },
    "blockchain": {
        "you_run": ["Только RPC/сеть из карточки", "Отладка на локальном форке"],
        "questions": ["Где проверка прав в контракте?"],
    },
    "warmup": {
        "you_run": ["Описание и вложения сначала", "Spawn: один IP:port, ping не ждать", "Браузер на web-UI"],
        "questions": ["Это файл, веб или смесь?"],
    },
    "machine": {
        "you_run": [
            "Один хост из карточки, не подсеть",
            "Порты → версии → один класс на сервис, не «всё сразу»",
        ],
        "questions": ["Что даёт foothold-класс, а не root с порога?"],
    },
}

# Soft-hints: куда смотреть в коде/UI. Никогда не строка атаки.
SOFT_HINT_RULES: list[tuple[tuple[str, ...], str]] = [
    (("ping", "traceroute", "admin utility"),
     "Если есть форма ping/traceroute — смотрите, уходит ли поле хоста в shell или в argv. "
     "Класс: инъекция в команду ОС. Защита: allowlist, без shell."),
    (("date format", "strftime", "cmd injection"),
     "Отличите библиотечный date()/strftime от вызова date(1) через shell. Allowlist формата."),
    (("{{", "mustache", "jinja", "freemarker", "ssti"),
     "Шаблон рядом с пользовательским вводом — класс SSTI. Смотрите, собирается ли шаблон из ввода."),
    (("strcpy", "gets(", "sprintf", "while(buf"),
     "Копирование без границы — класс переполнения. Смотрите размер буфера и терминирование в исходнике."),
    (("pickle", "unserialize", "yaml.load", "marshal"),
     "Десериализация недоверенного — класс insecure deserialization. Не воспроизводим входом."),
    (("devmode", "dev-mode", "debug=true", "disabled{{"),
     "Скрытый admin/debug часто за флагом режима, не за «секретным URL». Ищите, что выставляет флаг в шаблоне/конфиге."),
    (("upload", "multipart"),
     "Загрузка файлов: тип, имя, где лежит файл, исполняется ли каталог. Без тестовых веб-шеллов от агента."),
    (("lfi", "include", "path", "../"),
     "Путь из параметра — класс LFI/traversal. Смотрите нормализацию и allowlist имён."),
]


_ALIASES = {
    "forensic": "forensics", "rev": "reversing", "reverse": "reversing",
    "pwnable": "pwn", "webapp": "web", "steg": "forensics", "stego": "forensics",
    "warm-up": "warmup", "warm": "warmup",
}


def normalize_category(raw: str | None) -> str:
    c = (raw or "").strip().lower()
    c = _ALIASES.get(c, c)
    if c in ("htb", "box", "machine", "machines"):
        return "machine"
    if c in CATEGORIES:
        return c
    return ""


def detect_category(*, explicit: str = "", facts: dict | None = None,
                    ports: list | None = None, offline: bool = False,
                    ctf: bool = False) -> str:
    cat = normalize_category(explicit)
    if cat:
        return cat
    facts = facts or {}
    stored = normalize_category(str(facts.get("category") or ""))
    if stored:
        return stored
    if offline:
        return "reversing"
    ports = ports or []
    webish = False
    for p in ports:
        if not isinstance(p, dict):
            continue
        svc = str(p.get("service") or "").lower()
        port = int(p.get("port") or 0)
        if port in (80, 443, 8080, 8000, 8443, 3000, 5000) or "http" in svc:
            webish = True
    if webish:
        return "web"
    if ctf:
        return "warmup"
    return "machine"


def category_overlay(category: str) -> dict:
    return CATEGORY_STEPS.get(category) or {}


def soft_hints_for(*chunks: str, enabled: bool = False) -> list[str]:
    if not enabled:
        return []
    hay = " ".join(c for c in chunks if c).lower()
    if not hay.strip():
        return []
    out: list[str] = []
    for keys, hint in SOFT_HINT_RULES:
        if any(_key_hit(hay, k) if len(k) <= 4 else k.lower() in hay for k in keys):
            out.append(hint)
    return out[:5]
