# Lab Coach

Учебный defensive-ассистент для изолированного полигона. Версия пакета **1.8.0** (ТЗ 1.4 + Ollama/MCP/роли).

## Зачем этот агент на [Hack The Box](https://www.hackthebox.com/)

Lab Coach нужен, чтобы **заниматься на официальном hackthebox.com**: Starting Point и машины (VPN, профиль `htb`), Challenges и CTF Try Out (docker `IP:port` или файлы `offline`, профиль `ctf`).

Он ведёт сессию: одна цель из карточки, плейбук категории, gentle-скан своего инстанса, разбор **класса** дыры, заметки. Так вы проходите контент HTB **своими руками**, с преподавателем рядом.

Он **не** автосолвер: флаги, jailbreak, payload и сдачу формы агент не делает. Неофициальные зеркала не поддерживаются.

**Только lab.** Сканируются лишь адреса вашей учебной сети (RFC1918 / ULA / явно заданные lab CIDR).
Публичные IP отклоняются. Эксплойты не запускаются. Продукт не логинится и не меняет пароли.

Связанный продукт `security-scan-bot` — только импорт его `scan-*.json` через `explain` / `import-scanbot`,
без общего кода, токена и БД. Запрещён `from app...` импорт scan-bot: идеи копируем, пакет — нет.

## Быстрый старт (L0–L1)

```bash
cd lab-coach
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # впишите ADMIN_IDS=<ваш Telegram numeric id>
python -m lab_coach doctor
python -m lab_coach playbook reversing
python -m lab_coach plan 0 offline
python -m lab_coach class "date format"
python -m lab_coach session-init mytask offline
```

`doctor` / `playbook` / `plan` / `class` — без сети к цели. `scan` / `session-init` без `ADMIN_IDS` не стартуют (fail-closed).

## Конфигурация

См. `.env.example`. Главное:

- `LAB_PLATFORM=thm|htb|ctf|standoff365|hackthissite|vulnhub|metasploitable|custom`
- `ALLOWED_LAB_CIDRS` — **сужайте, не расширяйте**: для VirtualBox host-only например `192.168.56.0/24`.
  CIDR шире `/16` даёт предупреждение в `doctor`.
- `ALLOW_LOOPBACK=false` по умолчанию (loopback — только для отладки на своей машине).
- `SPAWNED_TARGET` — один явно заспавненный HTB docker (public). Пусто = public запрещён всегда.
- `REQUIRE_VPN=true` для `thm`/`htb` — **отказ скана**, если нет tun/tap с `10/8` (исключение: цель = `SPAWNED_TARGET`).
- `NMAP_ENABLED=false` по умолчанию; если включён — только `-sV -T4 --top-ports`, без NSE exploit-скриптов. Nuclei всегда с `-ni` и `-etags exploit,intrusive,dos` (и в CLI, и в MCP).
- `LLM_ENABLED=true` по умолчанию (OpenRouter/Ollama). `false` — только локальные шаблоны «Чем опасно», без сети к модели.
- `MAX_SCANS_PER_HOUR=20` — одна цель на вызов, списки/CIDR/подсети запрещены.

## Использование

```bash
# Скан lab-хоста (Metasploitable в host-only — своими словами: VM в host-only сети,
# IP гостя из вывода самой VM; без гайдов по эксплойтам)
python -m lab_coach scan 192.168.56.101
python -m lab_coach scan http://192.168.56.101/

# Разбор отчёта (своего или security-scan-bot) — без сети к цели
python -m lab_coach explain tests/fixtures/sample_report.json
python -m lab_coach import-scanbot path/to/scan-8.json

# Отказы
python -m lab_coach scan 8.8.8.8        # DENY + audit scan_denied
python -m lab_coach login foo           # нет такого действия + audit auth_action_denied
```

Отчёты: `data/reports/scan-<id>/` — JSON, MD, HTML. Аудит: sqlite (`DATABASE_URL`).

## MCP для агента (1.1)

Агент (Claude / Cursor / свой MCP-клиент) подключается **только stdio** на машине,
где поднят VPN/VM. Ключи OpenRouter — в env клиента, не в чат.

```json
{ "mcpServers": { "lab-coach": {
  "command": "python", "args": ["-m", "lab_coach.mcp"],
  "env": { "LAB_PLATFORM": "thm", "LLM_ENABLED": "true" }
} } }
```

См. `mcp_config.example.json` и `practice/MCP-AGENT-GUIDE.md`. Tools (15):
скан-слой — `get_lab_status`, `set_platform`, `scan_lab_target`,
`explain_mission`, `explain_report`, `import_scanbot_report`;
coach-слой методологии 0–6 — `init_session`, `session_status`, `log_note`,
`get_plan_step`, `read_session_file` (сессии в `HTB_DIR`, цель проверяется LabPolicy);
роли — `get_role_brief`, синие `harden_checklist`, `verify_fix`.
Режим Red vs Blue: `AGENT_ROLE=red|blue|coach` (матрица и сценарий — в `practice/RED-BLUE-GUIDE.md`).
Запрещённых tools (`run_exploit`, `msf_*`, `shell`, `login`, `set_password`, `run_kaligpt`, …) нет.

Сессия на площадке: человек поднимает VPN/VM → агент `get_lab_status` (если VPN нет на thm/htb —
просит подключить `.ovpn`, не сканирует) → человек даёт **один** IP из карточки комнаты/машины →
`scan_lab_target` → `explain_report` (класс дыры, что почитать; не пошаговый взлом).

Профили (§10.4):

| Профиль | Режим |
|---|---|
| `thm` | VPN; скан IP комнаты 10.x; `REQUIRE_VPN=true` |
| `htb` | VPN 10.10.10.0/23, 10.129.0.0/16; public docker только `SPAWNED_TARGET` |
| `ctf` | CTF-арена: только `SPAWNED_TARGET` (свой `IP:port`), всё остальное deny; плейбуки `get_ctf_playbook` |
| `standoff365` | VPN учений; один IP из брифа, не подсеть; bounty/прод — отказ |
| `hackthissite` | скан deny всегда; только `explain_mission` по вставленному тексту |
| `vulnhub`/`metasploitable` | своя VM, host-only CIDR |
| `custom` | `ALLOWED_LAB_CIDRS` |

## Смежные инструменты — рядом, не внутри (1.4)

KaliGPT и PentestGPT **не входят** в поставку: не форкаем, не submodule, не вызываем из CLI/MCP,
нет tools `run_kaligpt` / `run_pentestgpt`. Ставятся отдельно на Kali/AttackBox с другим API-ключом,
цель — только IP комнаты/VM. Заметки их сессий (markdown/JSON) можно разбирать через
`explain_report` / `explain_mission` — без повторного удара по цели. Не натравливать на прод,
`ita-sochi.ru`, Hack This Site, bounty Standoff, «вход без пароля».

## Ollama (локальные модели, v1.5.0)

Без облака и ключей: саммари пишет модель на твоей машине через OpenAI-совместимый endpoint Ollama.

```bash
# 1. Установка: https://ollama.com/download
# 2. Модель с хорошим русским (7B тянет и CPU, медленно; лучше GPU):
ollama pull qwen2.5:7b        # альтернативы: llama3.1:8b, mistral:7b, gemma2:9b
# 3. Демон (обычно уже запущен после установки):
ollama serve
# 4. Lab Coach на провайдер ollama:
LLM_PROVIDER=ollama OLLAMA_MODEL=qwen2.5:7b python -m lab_coach doctor
```

`doctor` покажет `llm_provider: ollama` и `ollama: {reachable, models}` — проверку, что демон жив и какие модели загружены.
Если демон недоступен, отчёты всё равно пишутся с локальным explain и пометкой «LLM недоступен» (F-LLM).
Переменные: `OLLAMA_BASE_URL` (умолч. `http://localhost:11434/v1`), `OLLAMA_MODEL`, опц. `OLLAMA_API_KEY`.
Свой прокси — через `LLM_PROVIDER=custom` + `OPENROUTER_BASE_URL`/`LLM_MODEL`.

## Практика (`practice/`)

- `LAB-VM-GUIDE.md` + `.env.metasploitable` — домашний полигон (Metasploitable 2 в host-only).
- `HTB-MACHINE-GUIDE.md` + `.env.htb` + `htb-check.sh` + `mcp_config.htb.example.json` — Hack The Box (Kali VM, VPN внутри гостя, профиль `htb`, fail-closed без tun0).
- `HTB-CHALLENGE-GUIDE.md` + `.env.htb-challenge` + `mcp_config.htb-challenge.example.json` — HTB Challenges (свой docker `IP:port` в `SPAWNED_TARGET`, VPN не нужен; без jailbreak и без `/flag.txt`).
- `htb-box/` — учебная уязвимая VM PlanBox под план recon→foothold→privesc (только host-only).
- `MAP-TO-MY-SITE.md` — как находки из lab превращать в действия на своём сайте без скана продакшена.
- `MCP-AGENT-GUIDE.md` — подключение ИИ-агента (Claude/Cursor) и пример coach-сессии.
- `RED-BLUE-GUIDE.md` — учения: красный и синий агенты, матрица ролей, 3 раунда.
- `CTF-ARENA-GUIDE.md` + `.env.ctf` + `mcp_config.ctf.example.json` — [CTF Try Out, ивент 1434](https://ctf.hackthebox.com/event/1434) (профиль `ctf`, только свой `SPAWNED_TARGET`).
- `ATTACK-DEFENSE-LAB.md` — программа «все классы атак + защита»: 16 модулей A–E с трекером (только легальные полигоны).

## Структура

```
lab_coach/  policy.py audit.py scanners.py llm.py explain.py reports.py
            importer.py platforms.py ratelimit.py secrets.py cli.py mcp.py tg.py
tests/      test_policy.py test_explain.py test_cli_mcp.py fixtures/sample_report.json
```

## Тесты

```bash
pytest -q
```

## Лицензия

MIT (код). Сканеры и модели — свои лицензии/ToS, см. `NOTICE`.
