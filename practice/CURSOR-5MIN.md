# Cursor / Claude Desktop за 5 минут

Lab Coach — **преподаватель**, не solver. Флаг на HTB сдаёте вы.

## 1. Установка

```bash
cd lab-coach
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env
# ADMIN_IDS=1   (любое число, fail-closed без него)
# LAB_PLATFORM=htb   или ctf
# SOFT_HINTS=true    # опционально: «куда смотреть», без payload
```

Проверка без клиента:

```bash
python -m lab_coach doctor
```

## 2. Cursor

Settings → MCP → Add new global MCP server:

```json
{
  "mcpServers": {
    "lab-coach": {
      "command": "python",
      "args": ["-m", "lab_coach.mcp"],
      "env": {
        "LAB_PLATFORM": "ctf",
        "ADMIN_IDS": "1",
        "HTB_DIR": "/home/kali/HTB",
        "MCP_TRANSPORT": "stdio",
        "SOFT_HINTS": "true"
      }
    }
  }
}
```

Для машин HTB: `LAB_PLATFORM=htb`, `REQUIRE_VPN=true`, `ALLOWED_LAB_CIDRS=10.10.10.0/23,10.129.0.0/16`.  
Для Challenges: `SPAWNED_TARGET=<IP:port>` с карточки.

Перезапустите Cursor. В чате должны появиться tools `init_session`, `next_action`, `ingest_output`.

Claude Desktop: тот же JSON в `claude_desktop_config.json`.

## 3. Пример диалога (Challenge web)

**Вы:** «Сессия routerweb, цель 10.20.0.5:30128, категория web.»

**Агент** вызывает `init_session(machine=routerweb, target=10.20.0.5:30128, category=web)`  
→ `next_action(routerweb, category=web)`.

**Вы** открываете `http://10.20.0.5:30128/` в браузере, копируете HTML.

**Агент:** `ingest_output(routerweb, http, <HTML>)` → `next_action`.

Дальше агент спрашивает: куда уходит ввод, есть ли скрытый admin, какой **класс** дыры.  
Он **не** пишет payload и **не** сдаёт флаг.

## 4. Если MCP «молчит»

Сервер говорит JSON-RPC с `Content-Length` (как LSP). Нужен lab-coach ≥ 1.9.0.  
Дымовуха:

```bash
python -c "import json,sys; m={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05'}}; b=json.dumps(m).encode(); sys.stdout.buffer.write(f'Content-Length: {len(b)}\r\n\r\n'.encode()+b)" \
  | python -m lab_coach.mcp | head
```

Должно ответить `Content-Length:` и `serverInfo.name = lab-coach`.
