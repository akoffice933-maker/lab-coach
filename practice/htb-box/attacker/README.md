# Машина атакующего — план действий (Kali)

Отсюда выполняются все шаги твоего `plan.txt`. Цель по умолчанию — PlanBox (`192.168.56.110`).
Правило скоупа: один стенд за сессию, чужие IP и интернет — запрещены.

## Этап 0. База

- Вариант Vagrant (как PlanBox, headless, работа через `vagrant ssh`):
  `cd attacker && vagrant up` (образ `kalilinux/rolling`, ~2–4 ГБ).
  После первого запуска: `vagrant snapshot save clean`.
- Вариант с GUI: готовый образ Kali (.ova) + вручную два адаптера (ниже).
- Ресурсы: 2 CPU, 4 ГБ ОЗУ.

## Этап 1. Сеть (важно)

- Адаптер 1 — **NAT** (интернет: обновления, `apt`, VPN наружу).
- Адаптер 2 — **host-only `vboxnet0`** (дорога к PlanBox; во Vagrant уже настроено через DHCP).
- Проверка: `ip a` → адрес `192.168.56.x` на втором интерфейсе; `ping -c3 192.168.56.110`.
- VPN под HTB поднимается **внутри этой же машины** (`~/vpn/*.ovpn`), но сессии не смешиваем:
  за раз либо PlanBox, либо выданная HTB-машина. `tun0` и host-only друг другу не мешают,
  мешают люди — веди `scope.txt`.

## Этап 2. Инструменты

```bash
./setup.sh   # внутри Kali: apt-пакеты под шаги плана + каталоги + venv под Lab Coach
```

Что ставит и зачем: `openvpn` (HTB VPN), `nmap` (шаг 1), `ffuf` + `gobuster` (шаг 1, веб-перебор),
`seclists` (словари: `/usr/share/seclists`), `exploitdb` (шаг 2, `searchsploit`), `nuclei` (шаг 1.5, связка с coach),
`python3-venv` (Lab Coach). Добивки вручную:

```bash
searchsploit -u                  # обновление базы (долго, один раз)
nuclei -update-templates         # шаблоны Nuclei (долго, один раз)
```

## Этап 3. Рабочее место

```bash
./session-init.sh 192.168.56.110
```

Создаёт `~/HTB/planbox/{nmap,loot,exploits,www}`, кладёт `scope.txt` и `notes.md` (шаблон —
в `notes-template.md`), печатает команды шага 0–1 с подставленной целью.
Lab Coach: скопируй проект в `~/lab-coach`, `python3 -m venv .venv`, `pip install -e ".[dev]"`,
`.env` — из `practice/.env.metasploitable` (PlanBox) или `practice/.env.htb` (HTB).

## Этап 4. Цикл сессии по plan.txt

| Шаг | Делает атакующая | Куда ложится |
|---|---|---|
| 0 | `ping`, `/etc/hosts`, каркас каталогов | `scope.txt`, `notes.md` |
| 1 | `nmap -p-`, затем `-sC -sV`; `ffuf` vhost; `gobuster` dir | `nmap/allports.txt`, `nmap/services.txt` |
| 1.5 | `lab-coach scan <IP>` | JSON привозим сюда на `explain` |
| 2 | браузер + `searchsploit <app> <ver>`, разбор бэкапов в `loot/` | `notes.md` |
| 3 | работа по вектору, креды — только в `loot/creds.txt` (не в git!) | `loot/` |
| 4–5 | энумерация/привилегии внутри цели, выводы — в `notes.md` | `notes.md`, `loot/` |
| 6 | оба флага, 3 строки «чему научился», откат стенда к снапшоту | `notes.md` |

Каталог `www/` — для файлов сессии (туда же кладёшь `linpeas.sh`, скачанный на Kali).

## Этап 5. Гигиена

- Креды, флаги, `.ovpn`, `.env` — никогда в git и чужие чаты.
- После сессии: `vagrant halt` (или гашение VM), стенд откатить к `clean`.
- Снапшот атакующей после удачной настройки — `configured`.
