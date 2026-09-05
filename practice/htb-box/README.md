# PlanBox — учебная VM под твой план (шаги 0–6)

Заведомо уязвимый стенд для твоего `plan.txt`. Каждый шаг плана здесь даёт артефакт:

| Шаг плана | Что даёт PlanBox |
|---|---|
| 0 — Подготовка | Статический IP `192.168.56.110`, имя `planbox.htb` (прописать в `/etc/hosts`) |
| 1 — Recon | Порты 22, 80 (`nmap -p-`); версии (`-sC -sV`); `robots.txt` → `/backup`, `/dev`; `ffuf` vhost находит `dev.planbox.htb`; `gobuster` находит `/login.php`, `/view.php`, `/backup/site-backup.zip` |
| 2 — Изучение | `phpinfo` в `/dev`, исходники в бэкапе (`deploy-notes.txt`, `config.php`), версия видна в заголовках |
| 3 — Foothold | Креды из бэкапа → веб-логин → reuse того же пароля в SSH (`student`). Альтернатива: LFI `view.php?page=` → чтение `config.php` |
| 4 — Энумерация | `~/user.txt`, стандартный набор (`id`, `sudo -l`, cron, SUID) |
| 5 — Privesc | Два учебных пути: `sudo NOPASSWD /usr/bin/find` и world-writable скрипт в cron. Оба — намеренные мис конфиги |
| 6 — Финал | `user.txt` + `root.txt` (формат `PLANBOX{...}`), шаблон заметок ниже |

## Безопасность (прочитать до запуска)

- Только **host-only** (`192.168.56.110`). Не вешать мост, не пробрасывать порты в интернет.
- Креды (`student / LabPractice2026!`) — только для этого стенда, нигде больше не использовать.
- До старта сделать снапшот чистой VM, после финала — откатить.
- Vagrant тянет базовый образ Ubuntu из официального каталога — это нормально (чистый апстрим, дыры создаёт только наш `box-build.sh`).

## Быстрый старт (Vagrant)

```bash
cd practice/htb-box
vagrant up          # ~5-10 мин: базовый образ + provision
vagrant snapshot save clean
./attacker/session-init.sh 192.168.56.110   # каркас ~/HTB/planbox на твоей Kali
```

Без Vagrant: подними Ubuntu 22.04 вручную, назначь host-only `192.168.56.110`
(netplan), скопируй внутрь `provision/box-build.sh` и запусти от root.

## Машина атакующего

Всё, откуда идут действия, — `attacker/`: отдельный `Vagrantfile` (Kali,
NAT + host-only), `setup.sh` (инструменты под шаги плана), `session-init.sh`,
шаблон `notes.md`. Полный план — в `attacker/README.md`.

## Связка с Lab Coach

Перед ручным recon прогони стенд через coach (профиль под host-only):

```bash
ALLOWED_LAB_CIDRS=192.168.56.0/24 LAB_PLATFORM=custom python -m lab_coach scan 192.168.56.110
```

JSON отчёта привози сюда — разберём `explain`.

## Финал (шаг 6) — шаблон

```text
Машина: planbox (192.168.56.110)
Foothold: <какой путь сработал>
Privesc: <какой путь сработал>
user.txt: PLANBOX{...}
root.txt: PLANBOX{...}
Чему научился (3 строки):
-
```

Детали intended-пути — в `SOLUTION.md` (открывать после своих попыток).
