"""Маскирование секретов перед LLM/отчётами (принцип textutil.mask_secrets)."""
from __future__ import annotations

import re

_PATTERNS = [
    # Authorization: Bearer xxx / Basic xxx / Token xxx
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s\"',;}]+)"), r"\1***"),
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-._~+/=]{8,})"), r"\1***"),
    # key=value секреты
    (re.compile(r"(?i)((?:api[_-]?key|secret|passwd|password|pwd|token|access[_-]?token|private[_-]?key)\s*[=:]\s*)([^\s\"',;}]+)"), r"\1***"),
    # JSON "password": "xxx"
    (re.compile(r"(?i)(\"?(?:password|passwd|secret|api[_-]?key|token)\"?\s*:\s*\")([^\"]+)(\")"), r"\1***\3"),
    # AWS-style
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***AWSKEY***"),
    # длинные hex/base64 похожие на секрет (осторожно, только с маркером ключа рядом уже покрыто;
    # здесь — cookie/session значения урезаем)
    (re.compile(r"(?i)((?:sessionid|session|cookie)\s*[=:]\s*)([^\s\"',;}]{12,})"), r"\1***"),
]


def mask_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    for rx, repl in _PATTERNS:
        out = rx.sub(repl, out)
    return out


def mask_obj(obj):
    if isinstance(obj, str):
        return mask_secrets(obj)
    if isinstance(obj, dict):
        return {k: mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v) for v in obj]
    return obj
