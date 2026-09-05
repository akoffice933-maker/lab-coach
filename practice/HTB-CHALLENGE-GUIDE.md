# HTB Challenges: docker spawn (`IP:port`), без VPN

Челленджи на [hackthebox.com](https://www.hackthebox.com/) (вкладка **Challenges**, не Machines)
поднимают **свой** docker с публичным адресом `IP:port`. VPN не нужен
([справка HTB](https://help.hackthebox.com/en/articles/8602725-understanding-the-hack-the-box-vpn)).

Пример карточки: сценарий вроде «Jailbreak / Pip-Boy», **Play through the browser**,
very easy, инстанс вида `203.0.113.50:30976`. Живой IP в git **не** кладём —
только то, что сейчас в карточке.

Lab Coach **не** jailbreak'ает устройство, не обходит биометрию и не читает `/flag.txt`.
Флаг сдаёт человек на сайте. Coach — scope, gentle-скан, класс задачи по тексту миссии.

## Человек (5 минут)

1. Spawn на карточке → скопировать **IP:port** (один инстанс на сессию).
2. Играть в браузере: `http://<IP>:<port>/` — это основной путь для web-UI челленджей.
3. Под Lab Coach:

```bash
cd lab-coach
cp practice/.env.htb-challenge .env
# впиши ADMIN_IDS и SPAWNED_TARGET=<IP:port> из карточки
python -m lab_coach doctor     # spawned_target_set=true, vpn_required_ok=true (исключение SPAWNED)
python -m lab_coach scan <IP:port>
```

4. Текст сюжета (без просьб «достань флаг») можно скормить `explain_mission` через MCP.
5. После сессии: остановить docker на сайте, в `.env` очистить `SPAWNED_TARGET=`.

Профиль `htb` + `REQUIRE_VPN=true`: скан **чужого** public IP — отказ; цель = `SPAWNED_TARGET` — ок, VPN не требуется.

Альтернатива — профиль `ctf` (`practice/.env.ctf`): разрешён **только** `SPAWNED_TARGET`, машины 10.129 не сканятся.

## MCP

См. `mcp_config.htb-challenge.example.json`. В env клиента:

```json
"LAB_PLATFORM": "htb",
"REQUIRE_VPN": "true",
"SPAWNED_TARGET": "<IP:port из карточки>",
"ADMIN_IDS": "<numeric id>"
```

Сессия методологии: `init_session(<slug>, <IP:port>)` — scope один инстанс.
Новый таск = новый `SPAWNED_TARGET` и новая сессия.

## Не делать

- Сканить подсеть, соседей, инфраструктуру HTB.
- Класть `.ovpn`, живой IP инстанса, флаги в git.
- Просить агента jailbreak / firmware / `/flag.txt` / «вход без пароля».
- Держать `SPAWNED_TARGET` после остановки docker — иначе scope на чужой (уже чужой) адрес.
