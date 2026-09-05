"""OpenRouter (OpenAI-compatible) клиент + постфильтр стоп-слов эксплойтов."""
from __future__ import annotations

import json
import logging
import urllib.request

log = logging.getLogger("lab_coach.llm")

SYSTEM_PROMPT = (
    "Ты — преподаватель кибербезопасности на изолированном учебном полигоне (Lab Coach). "
    "Отвечай по-русски, просто и по делу.\n"
    "НЕЛЬЗЯ: писать эксплойты, payload, shellcode, команды Metasploit (use/run/exploit), "
    "reverse shell, инструкции по обходу WAF вида «скопируй и запусти», "
    "инструкции «войти без пароля», смену пароля на чужой/учебной цели, обход авторизации, SQLi-логин, подмену сессии.\n"
    "МОЖНО: объяснить класс уязвимости, смысл severity/CVSS, чем опасно в lab, "
    "как в общих чертах воспроизвести на СВОЕЙ VM (без готового кода атаки), "
    "какие комнаты THM/HTB и темы почитать; напомнить, что свой пароль меняют штатно "
    "(админка CMS / панель хостинга), вне Lab Coach.\n"
    "Если пользователь просит атаку на прод/чужой хост, вход/смену пароля через уязвимость, "
    "готовый PoC или payload — откажи и предложи учебную альтернативу."
)

STOP_WORDS = (
    "msfvenom", "msfconsole", "reverse shell", "meterpreter",
    "exploit/", "/exploit", "shellcode", "use exploit",
)


def resolve_endpoint(s) -> tuple[str, str, str]:
    """Активный LLM-endpoint по LLM_PROVIDER.

    openrouter (default): OPENROUTER_BASE_URL + OPENROUTER_API_KEY + LLM_MODEL.
    ollama: OLLAMA_BASE_URL (default http://localhost:11434/v1) + OLLAMA_MODEL
        (default qwen2.5:7b). Ключ Ollama не нужен — подставляется заглушка.
    custom: OPENROUTER_BASE_URL как любой OpenAI-compatible URL + LLM_MODEL.
    Возвращает (base_url, api_key, model).
    """
    provider = (getattr(s, "llm_provider", "openrouter") or "openrouter").lower()
    if provider == "ollama":
        base = (getattr(s, "ollama_base_url", "") or "http://localhost:11434/v1").rstrip("/")
        model = getattr(s, "ollama_model", "") or "qwen2.5:7b"
        key = getattr(s, "ollama_api_key", "") or "ollama"
        return base, key, model
    return s.openrouter_base_url, s.openrouter_api_key, s.llm_model


def llm_configured(s) -> bool:
    """Есть ли чем говорить: ollama — всегда (проверка доступности отдельно), остальные — нужен ключ."""
    if not getattr(s, "llm_enabled", True):
        return False
    provider = (getattr(s, "llm_provider", "openrouter") or "openrouter").lower()
    if provider == "ollama":
        return True
    _, key, _ = resolve_endpoint(s)
    return bool(key)


def ollama_probe(base_url: str, timeout: int = 3) -> dict:
    """Жив ли Ollama: GET {base}/models. Никогда не бросает исключение."""
    url = base_url.rstrip("/") + "/models"
    try:
        import httpx  # type: ignore
        with httpx.Client(timeout=timeout) as c:
            r = c.get(url)
            if r.status_code != 200:
                return {"reachable": False, "models": []}
            data = r.json()
        models = [m.get("id", "?") for m in data.get("data", []) if isinstance(m, dict)]
        return {"reachable": True, "models": models}
    except ImportError:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("id", "?") for m in data.get("data", []) if isinstance(m, dict)]
            return {"reachable": True, "models": models}
        except Exception:
            return {"reachable": False, "models": []}
    except Exception:
        return {"reachable": False, "models": []}


def postfilter(text: str) -> str:
    """Если модель всё же выдала запрещённое — обрезать и заменить отказом."""
    low = (text or "").lower()
    if any(w in low for w in STOP_WORDS):
        return (
            "Ответ модели был отфильтрован: в нём обнаружены запрещённые материалы "
            "(эксплойт/payload/shell). Вместо этого — общий разбор:\n"
            "изучите класс уязвимости на своей lab-VM, проверьте обновления ПО, "
            "разберитесь с правами доступа и посмотрите соответствующие комнаты THM/HTB по теме."
        )
    return text


def _fallback_http(base_url: str, api_key: str, model: str, messages: list[dict],
                   timeout: int = 60, max_tokens: int = 1500) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/lab-coach",
        "X-Title": "Lab Coach",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""


def chat_completion(base_url: str, api_key: str, model: str, user_payload: str,
                    timeout: int = 60, max_tokens: int = 1500) -> str:
    """Вызов OpenRouter. Сначала httpx (если есть), иначе urllib. Без ретраев с дампом цели."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_payload},
    ]
    text = ""
    try:
        import httpx  # type: ignore
        with httpx.Client(timeout=timeout) as c:
            r = c.post(base_url.rstrip("/") + "/chat/completions",
                       headers={"Authorization": f"Bearer {api_key}",
                                "HTTP-Referer": "https://github.com/lab-coach",
                                "X-Title": "Lab Coach"},
                       json={"model": model, "messages": messages,
                             "temperature": 0.3, "max_tokens": max_tokens})
            r.raise_for_status()
            data = r.json()
        text = (data.get("choices", [{}])[0].get("message", {}).get("content") or "")
    except ImportError:
        text = _fallback_http(base_url, api_key, model, messages, timeout, max_tokens)
    return postfilter(text.strip())
