#!/usr/bin/env bash
# Preflight перед сессией HTB: VPN (tun0 10.x), openvpn, python, Lab Coach doctor.
# Запуск из корня репо внутри Kali VM:  ./practice/htb-check.sh
set -u
FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { say "  [OK] $*"; }
bad()  { say "  [FAIL] $*"; FAIL=1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

say "== 0. Каталог =="
ok "$ROOT"

say "== 1. TUN-интерфейс =="
if ip -o addr show 2>/dev/null | grep -Eq 'tun[0-9].*inet 10\.'; then
  ok "$(ip -o addr show | grep -Eo 'tun[0-9].*inet 10\.[0-9./]+' | head -1)"
else
  bad "нет tun0 с адресом 10.x — подними: sudo openvpn ~/Downloads/*.ovpn"
fi

say "== 2. Процесс openvpn =="
if pgrep -a openvpn >/dev/null 2>&1; then ok "$(pgrep -a openvpn | head -1)"; else bad "openvpn не запущен"; fi

say "== 3. Python / nuclei =="
command -v python3 >/dev/null && ok "python3 $(python3 --version 2>&1)" || bad "нет python3"
command -v nuclei >/dev/null && ok "nuclei $(nuclei -version 2>/dev/null | head -1)" \
  || say "  [..] nuclei нет в PATH — сканы пропустят шаг Nuclei с заметкой"

say "== 4. .env профиль htb =="
if [ ! -f .env ]; then
  bad "нет .env — скопируй: cp practice/.env.htb .env и впиши ADMIN_IDS"
else
  ok ".env на месте"
  grep -q '^LAB_PLATFORM=htb' .env && ok "LAB_PLATFORM=htb" || bad "LAB_PLATFORM не htb"
  grep -q '^REQUIRE_VPN=true' .env && ok "REQUIRE_VPN=true" || say "  [..] REQUIRE_VPN не true — скан без VPN не блокируется"
  if grep -Eq '^ADMIN_IDS=$' .env || ! grep -q '^ADMIN_IDS=' .env; then
    bad "ADMIN_IDS пуст — scan/explain не стартуют"
  else
    ok "ADMIN_IDS задан"
  fi
fi

say "== 5. Lab Coach doctor =="
if python3 -m lab_coach doctor >/tmp/lab-coach-doctor.out 2>&1; then
  ok "doctor exit 0"
  tail -30 /tmp/lab-coach-doctor.out
else
  bad "doctor упал"
  tail -30 /tmp/lab-coach-doctor.out
fi

[ "$FAIL" -eq 0 ] && say "ГОТОВ К СЕССИИ HTB" || say "СНАЧАЛА ЗАКРОЙ ПРОБЕЛЫ ВЫШЕ"
exit "$FAIL"
