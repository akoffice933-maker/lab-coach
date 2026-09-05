# MCP для ИИ-агента: подключение и сессия (v1.6.0)

Lab Coach отдаёт агенту (Claude / Cursor / свой MCP-клиент) 11 tools по stdio —
6 сканерно-объяснительных и 5 coach-сессий по шагам `plan.txt` 0–6.

## Что умеет агент

| Tool | Назначение |
|---|---|
| `get_lab_status` | платформа, CIDR, VPN-guess, сканеры, LLM (без секретов) |
| `set_platform` | `thm\|htb\|standoff365\|hackthissite\|vulnhub\|metasploitable\|custom` |
| `scan_lab_target` | скан ОДНОЙ lab-цели (политика + лимит 20/час) |
| `explain_mission` | разбор текста миссии как учитель |
| `explain_report` | разбор findings без сети к цели |
| `import_scanbot_report` | импорт `scan-*.json` прод-бота |
| `init_session` | сессия: `HTB_DIR/<machine>/{nmap,loot,exploits,www}` + `scope.txt` + `notes.md` (цель проверяется LabPolicy) |
| `session_status` | файлы сессии, готовность шагов, что делать дальше |
| `log_note` | дописать заметку в `notes.md` (шаг 0–6) |
| `get_plan_step` | методология шага: recon-команды с подставленной целью, чек-листы (без пейлоадов) |
| `read_session_file` | прочитать файл сессии (за пределы каталога — отказ) |

Чего у агента НЕТ и не будет: `run_exploit`, `msf_*`, `shell`, `login`,
`set_password`, `run_kaligpt`, `run_pentestgpt` — запрос такого tool возвращает отказ.

## Подключение

Сервер запускается там же, где VPN/VM (stdio, ключи — в env, не в чат):

```json
{ "mcpServers": { "lab-coach": {
  "command": "python",
  "args": ["-m", "lab_coach.mcp"],
  "env": {
    "LAB_PLATFORM": "custom",
    "ALLOWED_LAB_CIDRS": "192.168.56.0/24",
    "HTB_DIR": "/home/kali/HTB",
    "LLM_PROVIDER": "ollama",
    "OLLAMA_MODEL": "qwen2.5:7b",
    "MCP_TRANSPORT": "stdio"
  }
} } }
```

- **Claude Desktop**: файл конфига — Linux `~/.config/Claude/claude_desktop_config.json`,
  macOS `~/Library/Application Support/Claude/claude_desktop_config.json`,
  Windows `%APPDATA%\Claude\claude_desktop_config.json`. После правки — перезапустить.
- **Cursor**: Settings → MCP → Add new global MCP server → тот же JSON.
- Проверка без клиента (дымовуха stdio):
  `printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python -m lab_coach.mcp`

## Пример сессии (PlanBox)

Человек: «начинаем planbox 192.168.56.110».
Агент: `init_session(planbox, 192.168.56.110)` → `get_plan_step(0)` → диктует ping/hosts.
Человек выполняет руками, кидает выводы. Агент: `log_note(...)` → `session_status` →
видит `next: 1 recon` → `get_plan_step(1, 192.168.56.110)` → диктует nmap с подставленным IP.
Находки: `scan_lab_target` → `explain_report`. Тупик: `read_session_file(planbox, nmap/services.txt)` →
смотрит сам и подсказывает следующий чек-лист.

## Правила для агента (скажи ему это один раз)

1. Один стенд — одна сессия (`scope.txt` — закон).
2. Команды выполняешь ТЫ (человек), агент только планирует, читает выводы и ведёт notes.
3. Просьбы «войти без пароля / сменить пароль / дай пейлоад» агент отклоняет (так настроен слой).
4. Флаги вводишь на сайте/в notes вручную, агент их не «добывает».
