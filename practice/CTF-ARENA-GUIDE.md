# CTF Try Out HTB — ивент 1434 (профиль `ctf`)

Площадка: [ctf.hackthebox.com/event/1434](https://ctf.hackthebox.com/event/1434)  
Описание: [CTF Try Out](https://ctf.hackthebox.com/event/details/ctf-try-out-1434) — демо-арена HTB, вход без пароля ивента, команда до 5.

Категории Try Out (по [гайду HTB](https://help.hackthebox.com/en/articles/5200851-ctf-user-s-guide)): **Warmup**, Web, Forensics, Reversing, Misc, Crypto.  
Docker: публичный `IP:port`, **VPN не нужен**, **ping не отвечает** — только указанный порт.  
Zip вложений: пароль площадки всегда `hackthebox`. Флаг обычно `HTB{...}`, сдаёт **человек** в форме ивента.

Lab Coach нужен, чтобы **учиться на официальном HTB** (не «проходить сайт за вас»): scope, плейбук, заметки, класс уязвимости. Флаги и эксплойты — человек. Неофициальные зеркала не используем.

## Правила

Не атаковать инфраструктуру платформы и другие команды, не брутить форму сдачи флагов,
не делиться флагами/райтапами с другими командами, никакого DDoS и агрессивных сканов,
одна команда на ивент. Флаги — только в `loot/flags.txt` сессии (не в git).

## Настройка

1. Sign Up на ивенте 1434 → join/создать команду.
2. Начать с **Warmup** → Spawn Docker → скопировать `IP:port`.
3. Играть в браузере / клиенте по карточке.
4. Lab Coach:

```bash
cd lab-coach
cp practice/.env.ctf .env
# ADMIN_IDS и SPAWNED_TARGET=<IP:port из карточки>
python -m lab_coach doctor          # platform: ctf, spawned_target_set: true
python -m lab_coach scan <IP:port>  # свой инстанс — ок; любой другой — отказ
```

5. Новый таск = новый `SPAWNED_TARGET` + `init_session(<slug>, <IP:port>)`. Старый IP очистить.
6. **Файловые таски без docker** (Reversing / Crypto / Forensics, напр. zip с `satellite` + `.so`):  
   `init_session(satellitehijack, offline)` — сеть не сканировать, бинарь **не** запускать на хосте.  
   Плейбук: `get_ctf_playbook(reversing)`.
7. Fullpwn-машины на CTF (если появятся) — это VPN и профиль `htb`, не `ctf`.

MCP: `mcp_config.ctf.example.json` (`LAB_PLATFORM=ctf`, подставить `SPAWNED_TARGET`).

## Как играем вместе (контракт)

| Делаете вы | Делает Lab Coach / этот чат |
|---|---|
| Spawn, браузер, файлы таска, сдача флага | `get_ctf_playbook`, gentle-скан своего инстанса, класс находки |
| Команды руками | `explain_mission` по тексту описания (без «достань флаг») |
| notes / loot | `log_note`, `session_status` |

Пришлите: **категория + название таска + IP:port** (без просьбы решить). Дальше — плейбук категории и scope, не walkthrough.

## Агенты

- **Triage:** `get_ctf_playbook(web|pwn|crypto|forensics|reversing|misc|osint|blockchain)`
- **Web:** один `scan_lab_target(IP:port)`, не флудить
- **Офлайн** (pwn/crypto/forensics/reversing): файлы качаете вы; бинарь не запускать на хосте
- **Blue:** `explain_report` + `harden_checklist`

## Типичные ошибки

- Скан без `SPAWNED_TARGET` → отказ
- Несколько инстансов в одной сессии → нет
- `nmap -p-` / ping инстанса → ping молчит, порт только из карточки
- Живой IP и флаги в git → нет
