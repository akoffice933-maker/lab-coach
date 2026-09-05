# Сухой прогон агента на CTF Try Out (без живых IP)

Не сканируем чужие/текущие docker HTB из чата. Прогон — на DOCUMENTATION IP `203.0.113.50:30445`.

```bash
cd lab-coach
cp practice/.env.ctf .env
# ADMIN_IDS; SPAWNED_TARGET=203.0.113.50:30445
python -m lab_coach doctor
python -m pytest -q tests/test_ctf.py tests/test_explain.py tests/test_htb.py
```

Ожидаемо:
- `warmup` / `web` плейбуки не Generic
- `get_plan_step(0)` в профиле `ctf` **без ping -c3**
- `explain_mission` не отваливается на слове «обход» в теории
- скан **чужого** public — deny; своего SPAWNED — allow (Nuclei может быть skipped)

Живой TimeKORP (`154…`) в `.env` только у вас локально, не в git. Агент не добывает флаг.
