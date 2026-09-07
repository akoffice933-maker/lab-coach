# Docker-lab за 5 минут (Juice Shop)

Metasploitable 2 — отдельная VM (см. `LAB-VM-GUIDE.md`). Для быстрого старта — OWASP Juice Shop в compose.

```bash
cd lab-coach
docker compose up -d
cp practice/.env.docker .env
python -m lab_coach doctor
python -m lab_coach session-init juiceshop 172.30.0.10 --category web
python -m lab_coach next juiceshop --category web
# браузер: http://127.0.0.1:3000/  (скан цели — 172.30.0.10:3000)
python -m lab_coach scan http://172.30.0.10:3000/
```

С хоста контейнер на `172.30.0.10` (сеть `lab`). Публичный интернет compose не публикует: порт 3000 только на `127.0.0.1`.

Lab Coach **не** логинится в Juice Shop и не выдаёт решения заданий. Класс находки — `class` / `explain`.
