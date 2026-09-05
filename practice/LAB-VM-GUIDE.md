# Домашний полигон: Metasploitable 2 + Lab Coach

Цель: учебный двойник серверной части — сканируем и разбираем его, **публичный сайт не трогаем**.
Эксплойты не запускаем: работаем на уровне «скан → класс находки → как закрывается».

## Что понадобится

- ПК (Windows / Linux / macOS), ~10 ГБ свободно, 2 ГБ ОЗУ под VM.
- VirtualBox: https://www.virtualbox.org/wiki/Downloads
- Образ Metasploitable 2 (833 МБ): http://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip/download
  (зеркало: https://download.vulnhub.com/metasploitable/metasploitable-linux-2.0.0.zip) [3](https://www.vulnhub.com/entry/metasploitable-2,29/)
- Проект Lab Coach из этой папки (`lab-coach/`) — скопируй его на свой ПК.

## Шаг 1. Host-only сеть

1. Установи VirtualBox.
2. Открой *Файл → Host Network Manager* — там обычно уже есть `vboxnet0` на `192.168.56.1`, маска `255.255.255.0`. Если нет — создай и задай эти адреса вручную, DHCP можно выключить.
3. Это и есть твой полигон: хост `192.168.56.1`, гость получит адрес из `192.168.56.0/24`.

## Шаг 2. Скачай и проверь образ

1. Скачай `metasploitable-linux-2.0.0.zip` (~833 МБ) и распакуй.
2. Сверь контрольную сумму архива/файлов: MD5 `8825F2509A9B9A58EC66BD65EF83167F` [3](https://www.vulnhub.com/entry/metasploitable-2,29/).
   Windows (PowerShell): `Get-FileHash file.zip -Algorithm MD5`. Linux/macOS: `md5sum file.zip`.

## Шаг 3. Создай VM

1. *Машина → Создать*: имя `Metasploitable 2`, тип Linux / Ubuntu 64-bit, ОЗУ 1024–2048 МБ.
2. Жёсткий диск → *использовать существующий* → выбери распакованный `.vmdk`.
3. *Настроить → Сеть → Адаптер 1*: **Host-only**, имя `vboxnet0`. Больше ничего не включай:
   NAT/мост не нужны, в интернет эта VM ходить не должна [2](https://eaglepubs.erau.edu/mastering-enterprise-networks-labs/chapter/metasploitable-3/).
4. Сделай снапшот чистого состояния (*Снимки → Сделать*) — пригодится для отката.

## Шаг 4. Запусти и узнай IP

1. Стартуй VM, дождись приглашения входа.
2. Войди в консоль штатной учёткой образа (`msfadmin` / `msfadmin` — это дефолт самого образа для настройки своей VM) и выполни `ifconfig`. Адрес вида `192.168.56.101` — твоя цель.
3. С хоста проверь: `ping 192.168.56.101`.

> VM живёт только в host-only. Не переключай её в мост/NAT «чтобы было удобнее» — это выведет заведомо дырявую машину в твою домашнюю сеть/интернет.

## Шаг 5. Настрой Lab Coach на своём ПК

```bash
cd lab-coach
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp practice/.env.metasploitable .env
# в .env впиши свой ADMIN_IDS
python -m lab_coach doctor
```

`practice/.env.metasploitable` уже содержит:

```text
LAB_PLATFORM=metasploitable
ALLOWED_LAB_CIDRS=192.168.56.0/24
LLM_ENABLED=false        # включи true + ключ позже, когда дойдёшь до саммари
```

## Шаг 6. Первый цикл

```bash
python -m lab_coach scan 192.168.56.101
python -m lab_coach explain data/reports/scan-1/scan-1.json
```

Отчёт упадёт в `data/reports/scan-1/` (JSON + MD + HTML).

## Упражнения (безопасные)

1. **Карта классов.** Выпиши из отчёта 5 классов находок своими словами: что это, чем опасно в lab.
2. **Устаревшее ПО.** Найди в отчёте пункт про версии → открой админку *своего* сайта и сверь версии CMS/модулей/PHP с актуальными. Обнови, что отстало.
3. **Слабый вход.** Находка про дефолтные учётки → проверь свою админку: длинный уникальный пароль, 2FA, смена стандартного адреса админки, бэкап перед изменениями.
4. **Заголовки и TLS.** Класс «HTTP-заголовки/TLS» из отчёта → открой свой сайт в браузере (вкладка Сеть в devtools): какие заголовки отдаются, какой сертификат и протокол. Сверь с чек-листом в `MAP-TO-MY-SITE.md`.
5. **Приоритеты.** Отсортируй находки lab-отчёта по severity и напиши для каждой одну строку «что чинить первым на проде и почему».

Привози JSON-отчёты сюда — разберём командой `explain` вместе.
