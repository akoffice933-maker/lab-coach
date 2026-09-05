#!/usr/bin/env bash
# Preflight перед сессией HTB: VPN (tun0 10.x), openvpn, python, Lab Coach doctor.
# Запуск внутри Kali VM:  ./practice/htb-check.sh
FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { say "  [OK] $*"; }
bad()  { say "  [FAIL] $*"; FAIL=1; }

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

say "== 4. Lab Coach doctor =="
if [ -f .env ]; then
  python3 -m lab_coach doctor 2>&1 | tail -25
else
  bad "нет .env — скопируй: cp practice/.env.htb .env и впиши ADMIN_IDS"
fi

[ "$FAIL" -eq 0 ] && say "ГОТОВ К СЕССИИ" || say "СНАЧАЛА ЗАКРОЙ ПРОБЕЛЫ ВЫШЕ"
exit "$FAIL"
