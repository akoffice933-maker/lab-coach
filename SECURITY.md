# SECURITY — Lab Coach

## Модель угроз

Lab Coach — преподаватель для полигона, не атакующий агент. Угрозы, от которых защищаемся:

1. **Скан чужого интернета** из lab-инструмента → invert-политика: только `ALLOWED_LAB_CIDRS`,
   `is_global` deny всегда, смешанный DNS deny, metadata/link-local deny, loopback deny по умолчанию.
2. **Эксплуатация** → нет Metasploit/payload/listener/session; нет генерации PoC/shellcode моделью;
   постфильтр стоп-слов (`msfvenom`, `reverse shell`, …).
3. **Вход/смена пароля на цели** → нет login/cookie/set-password кода и tools; запросы вида
   «вход без пароля» → отказ + `audit.auth_action_denied`. Свой пароль — только штатно
   (админка CMS / панель хостинга), вне продукта.
4. **Утечка секретов** → ключ только из env, `mask_secrets` перед LLM, `doctor` без секретов,
   `.env` в `.gitignore`.
5. **MCP «на весь мир»** → только `stdio`, `refuse_non_stdio` (`MCP_TRANSPORT!=stdio` / `FASTMCP_HOST` → SystemExit).
6. **Путаница с прод-ботом** → отдельный репо/`.env`/`data`, другой Telegram-токен, запрет импорта `app.*` scan-bot.

## Правила оператора (дисклеймер)

- Цели: ваши VM либо официальный полигон в рамках правил площадки
  (THM / HTB / Standoff 365 учения / HTS миссии / VulnHub / Metasploitable в своей VM).
- Баг-баунти Standoff на реальных бизнес-системах — НЕ lab-скан из коробки.
- Сканирование чужих хостов «для учёбы» не допускается. Нарушение ToS площадки — ответственность оператора.

## Сообщить об уязвимости

Откройте issue в репозитории с пометкой `[security]` без PoC по чужим системам.
