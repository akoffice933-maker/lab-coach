# Машина под Hack The Box: Kali VM + VPN + Lab Coach (профиль htb)

Принцип тот же, что везде в Lab Coach: сканируем **только IP, выданный тебе карточкой машины**.
Подсети, чужие машины и инфраструктуру VPN не трогаем — это ToS площадки и твоя ответственность.

## Вариант А (рекомендую): своя Kali VM

1. **VirtualBox**: https://www.virtualbox.org/wiki/Downloads (+ Extension Pack).
2. **Готовый образ Kali** — устанавливать ничего не надо: kali.org → *Get Kali* → *Virtual Machines* → образ под VirtualBox (~3 ГБ, распакуй и открой `.vbox`) [2](https://www.logeshwaran.org/2026/08/install-kali-linux-in-virtualbox-latest.html). Качай только с kali.org. Дефолтный вход образа: `kali` / `kali` — смени пароль после первого входа (`passwd`).
3. Ресурсы VM: 2 CPU, 2–4 ГБ ОЗУ, 30+ ГБ диска. Сеть VM — **NAT** (интернет для обновлений), VPN поднимем поверх внутри гостя.
4. Внутри Kali обновись: `sudo apt update && sudo apt install -y openvpn nuclei python3-venv`.

## Вариант Б (без своей VM): Pwnbox

Браузерная Kali от HTB, VPN поднимается сам. У free-аккаунтов — одна сессия 120 минут на всё время [1](https://help.hackthebox.com/en/articles/6007919-introduction-to-starting-point).
Для первой комнаты сойдёт, для регулярной учёбы — вариант А.

## Подключение VPN (вариант А)

1. На сайте HTB открой Starting Point / нужную машину → кнопка **OpenVPN** → выбери сервер доступа и протокол (**TCP стабильнее**) → **Download VPN** [1](https://help.hackthebox.com/en/articles/6007919-introduction-to-starting-point).
2. Файл `.ovpn` положи **внутрь Kali VM** (не на хост) и подними там:
   `sudo openvpn ~/Downloads/lab-XXX.ovpn`
3. Жди `Initialization Sequence Completed`. **Терминал не закрывай** — закроешь, VPN упадёт [1](https://help.hackthebox.com/en/articles/6007919-introduction-to-starting-point).
4. Проверка в новом терминале:
   - `ip a show tun0` — должен быть адрес из `10.x`;
   - `./practice/htb-check.sh` — наш префлайт (tun, openvpn, python, doctor).

> Один `.ovpn` — одно подключение. Вторую копию рядом не поднимай, будет конфликт [3](https://www.reddit.com/r/hackthebox/comments/138fzfg/cant_connect_to_openvpn/). Файл VPN никому не передавай и в git не клади.

## Lab Coach в профиле htb

```bash
cd lab-coach
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp practice/.env.htb .env      # впиши свой ADMIN_IDS (не оставляй пустым)
./practice/htb-check.sh        # tun0 10.x, openvpn, doctor
python -m lab_coach doctor     # platform=htb, vpn_required_ok=true, likely_vpn=true
```

CLI и MCP **сами читают `.env`** (не нужно `export $(cat .env)`).

`.env.htb` уже содержит:

```text
LAB_PLATFORM=htb
REQUIRE_VPN=true
ALLOWED_LAB_CIDRS=10.10.10.0/23,10.129.0.0/16
```

`REQUIRE_VPN=true` — **отказ скана**, если нет tun/tap с 10/8 (не только предупреждение).
Исключение: цель = `SPAWNED_TARGET` (challenge/Academy docker с публичным IP:port, VPN не нужен).

MCP для агента на Kali: скопируйте `mcp_config.htb.example.json` в конфиг Claude/Cursor, подставьте `ADMIN_IDS` и `HTB_DIR`.

## Цикл сессии

1. На сайте HTB заспавнь машину → возьми **её IP из карточки** (например `10.129.X.Y`).
2. `python -m lab_coach scan 10.129.X.Y` — одна цель, лимит 20/час.
3. `python -m lab_coach explain data/reports/scan-N/scan-N.json` — разбор классов, что почитать.
4. Флаги вводишь **вручную на сайте**. Дальнейшие шаги по машине — своими силами и головой: Lab Coach подсказывает классы и теорию, не прохождение.
5. Docker-челленджи с **публичным IP** (не VPN): только если это твой заспавненный инстанс — впиши его IP в `SPAWNED_TARGET` в `.env` на время сессии, потом очисти. Пустой `SPAWNED_TARGET` = public запрещён всегда.

## Чек-лист «не навреди»

- [ ] VPN поднят внутри Kali, `tun0` с адресом 10.x есть
- [ ] Сканирую только IP из своей карточки, не подсеть и не «соседа»
- [ ] `.ovpn` и `.env` не в git, ключи не в чатах
- [ ] Pwnbox/VM гашу после сессии, машину на сайте останавливаю
