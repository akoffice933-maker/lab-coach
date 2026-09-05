"""Конфигурация Lab Coach (env-only, fail-closed по ADMIN_IDS для действий)."""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field


DEFAULT_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8"
VALID_PLATFORMS = ("thm", "htb", "standoff365", "hackthissite", "vulnhub", "metasploitable", "custom", "ctf")

# Профили площадок: сужающие CIDR (норматив 1.2 / §10.4).
# Это НЕ открытие интернета, только сужение lab-диапазонов.
PLATFORM_CIDRS: dict[str, list[str]] = {
    "thm": ["10.0.0.0/8"],
    "htb": ["10.10.10.0/23", "10.129.0.0/16"],
    # Standoff 365 учения: встречались 10.154/16, 10.124/16 — задаём как дефолт профиля,
    # оператор уточняет конкретный диапазон брифа через ALLOWED_LAB_CIDRS.
    "standoff365": ["10.154.0.0/16", "10.124.0.0/16"],
    "hackthissite": [],  # scan deny: только explain_mission
    "vulnhub": ["192.168.56.0/24", "192.168.0.0/16", "10.0.0.0/8"],
    "metasploitable": ["192.168.56.0/24", "192.168.0.0/16", "10.0.0.0/8"],
    "custom": [],
    # ctf: скан deny по умолчанию; единственный exception — SPAWNED_TARGET (свой инстанс).
    "ctf": [],
}

METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.google.com",
    "metadata.goog",
    "instance-data",
    "169.254.169.254",
}


def load_dotenv(path: str | None = None) -> str:
    """Прочитать KEY=VAL из .env в os.environ, не перезаписывая уже заданное.
    Без python-dotenv: иначе `cp practice/.env.htb .env` не работал бы для CLI/MCP."""
    p = path or os.environ.get("LAB_COACH_ENV") or ".env"
    if not p or not os.path.isfile(p):
        return ""
    try:
        with open(p, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return ""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key and key not in os.environ:
            os.environ[key] = val
    return p


def _getenv(name: str, default: str = "") -> str:
    v = os.environ.get(name, default)
    return v if v is not None else default


def _getbool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _getint(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)).strip())
    except (ValueError, AttributeError):
        return default


@dataclass
class Settings:
    admin_ids: list[str] = field(default_factory=list)
    lab_platform: str = "custom"
    require_vpn: bool = False
    spawned_target: str = ""
    max_scans_per_hour: int = 20
    allowed_lab_cidrs_raw: str = DEFAULT_CIDRS
    allow_loopback: bool = False
    nuclei_path: str = "nuclei"
    nmap_enabled: bool = False
    scan_timeout_seconds: int = 900
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "openai/gpt-4o-mini"
    llm_enabled: bool = True
    llm_provider: str = "openrouter"
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "qwen2.5:7b"
    ollama_api_key: str = ""
    bot_token: str = ""
    environment: str = "lab"
    # Корень сессий методологии (coach-слой MCP). Только локальные файлы.
    htb_dir: str = "~/HTB"
    # Роль агента: coach (всё) | red (атакующий) | blue (защитник)
    agent_role: str = "coach"
    log_level: str = "INFO"
    database_url: str = "sqlite+aiosqlite:///./data/lab.db"
    mcp_transport: str = "stdio"

    @property
    def effective_cidrs(self) -> list[str]:
        """CIDR процесса: профиль площадки сужает ALLOWED_LAB_CIDRS, не расширяет."""
        raw = [c.strip() for c in self.allowed_lab_cidrs_raw.split(",") if c.strip()]
        if self.lab_platform in PLATFORM_CIDRS and PLATFORM_CIDRS[self.lab_platform]:
            profile = PLATFORM_CIDRS[self.lab_platform]
            try:
                profile_nets = [ipaddress.ip_network(c, strict=False) for c in profile]
                env_nets = [ipaddress.ip_network(c, strict=False) for c in raw]
            except ValueError:
                return raw
            # Пересечение: оставляем только env-сети, покрытые профилем (сужение).
            narrowed: list[str] = []
            for en in env_nets:
                for pn in profile_nets:
                    if en.version != pn.version:
                        continue
                    if en.subnet_of(pn) or en == pn:
                        narrowed.append(str(en))
                        break
                    if pn.subnet_of(en):
                        narrowed.append(str(pn))
                        break
            return narrowed or profile
        if self.lab_platform in ("hackthissite", "ctf"):
            # hackthissite: скан deny; ctf: разрешён ТОЛЬКО SPAWNED_TARGET (см. policy).
            return []
        return raw


def runtime_state_path() -> str:
    return _getenv("LAB_COACH_STATE", "./data/runtime-state.json") or "./data/runtime-state.json"


def read_runtime_state() -> dict:
    path = runtime_state_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_runtime_state(**kw) -> str:
    """Сохранить ключи runtime (lab_platform) — переживает рестарт MCP."""
    path = runtime_state_path()
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    data = read_runtime_state()
    for k, v in kw.items():
        if v is None:
            data.pop(k, None)
        else:
            data[k] = v
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return path


def load_settings() -> Settings:
    load_dotenv()
    admin_raw = _getenv("ADMIN_IDS", "").strip()
    admin_ids = [a.strip() for a in admin_raw.replace(";", ",").split(",") if a.strip()]
    state = read_runtime_state()
    # runtime-state (set_platform) важнее env, иначе mcp.json затирает профиль при рестарте.
    if state.get("lab_platform"):
        platform = str(state.get("lab_platform")).strip().lower() or "custom"
    else:
        platform = _getenv("LAB_PLATFORM", "custom").strip().lower() or "custom"
    if platform not in VALID_PLATFORMS:
        platform = "custom"
    provider = _getenv("LLM_PROVIDER", "openrouter").strip().lower() or "openrouter"
    if provider not in ("openrouter", "ollama", "custom"):
        provider = "openrouter"
    role = _getenv("AGENT_ROLE", "coach").strip().lower() or "coach"
    if role not in ("coach", "red", "blue"):
        role = "coach"
    return Settings(
        admin_ids=admin_ids,
        lab_platform=platform,
        require_vpn=_getbool("REQUIRE_VPN", False),
        spawned_target=_getenv("SPAWNED_TARGET", "").strip(),
        max_scans_per_hour=_getint("MAX_SCANS_PER_HOUR", 20),
        allowed_lab_cidrs_raw=_getenv("ALLOWED_LAB_CIDRS", DEFAULT_CIDRS),
        allow_loopback=_getbool("ALLOW_LOOPBACK", False),
        nuclei_path=_getenv("NUCLEI_PATH", "nuclei"),
        nmap_enabled=_getbool("NMAP_ENABLED", False),
        scan_timeout_seconds=_getint("SCAN_TIMEOUT_SECONDS", 900),
        openrouter_api_key=_getenv("OPENROUTER_API_KEY", ""),
        openrouter_base_url=_getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/"),
        llm_model=_getenv("LLM_MODEL", "openai/gpt-4o-mini"),
        llm_enabled=_getbool("LLM_ENABLED", True),
        llm_provider=provider,
        ollama_base_url=_getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1").rstrip("/"),
        ollama_model=_getenv("OLLAMA_MODEL", "qwen2.5:7b"),
        ollama_api_key=_getenv("OLLAMA_API_KEY", ""),
        bot_token=_getenv("BOT_TOKEN", ""),
        environment=_getenv("ENVIRONMENT", "lab"),
        htb_dir=_getenv("HTB_DIR", "~/HTB"),
        agent_role=role,
        log_level=_getenv("LOG_LEVEL", "INFO"),
        database_url=_getenv("DATABASE_URL", "sqlite+aiosqlite:///./data/lab.db"),
        mcp_transport=_getenv("MCP_TRANSPORT", "stdio"),
    )


def require_admin_configured(s: Settings) -> None:
    """Fail-closed: без ADMIN_IDS действия (scan/explain/telegram) не стартуют."""
    if not s.admin_ids:
        raise SystemExit(
            "ADMIN_IDS пуст — процесс не стартует (fail-closed). "
            "Задайте ADMIN_IDS=<ваш Telegram numeric id> в .env. "
            "Команда doctor доступна для проверки конфигурации."
        )


def db_path_from_url(url: str) -> str:
    # sqlite+aiosqlite:///./data/lab.db  / sqlite:///./data/lab.db / путь
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if url.startswith(prefix):
            return url[len(prefix):] or "./data/lab.db"
    if url.startswith("sqlite"):
        # неизвестный вариант — fallback
        return "./data/lab.db"
    return url
