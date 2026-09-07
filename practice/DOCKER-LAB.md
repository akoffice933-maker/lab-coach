# Docker-lab за 5 минут (Juice Shop + DVWA)

Metasploitable 2 — отдельная VM (см. `LAB-VM-GUIDE.md`). Здесь два web-стенда в одной сети `172.30.0.0/24`.

| Сервис | IP в lab | Браузер на хосте | Категория |
|---|---|---|---|
| OWASP Juice Shop | `172.30.0.10:3000` | http://127.0.0.1:3000/ | web, современный JS |
| DVWA | `172.30.0.11:80` | http://127.0.0.1:4280/ | web, классика (SQLi/XSS учебные уровни) |

Порты на хосте только `127.0.0.1`. Скан Lab Coach — по **lab-IP**, не по localhost (loopback по умолчанию запрещён).

```bash
cd lab-coach
docker compose up -d
cp practice/.env.docker .env
python -m lab_coach doctor

python -m lab_coach session-init juiceshop 172.30.0.10 --category web
python -m lab_coach next juiceshop --category web
python -m lab_coach scan http://172.30.0.10:3000/

python -m lab_coach session-init dvwa 172.30.0.11 --category web
python -m lab_coach scan http://172.30.0.11/
```

Lab Coach **не** логинится в Juice Shop/DVWA и не выдаёт решения заданий. Класс находки — `class` / `explain`. Soft hints:

```bash
SOFT_HINTS=true python -m lab_coach ingest juiceshop http --file loot/index.html
SOFT_HINTS=true python -m lab_coach next juiceshop --category web
```
