#!/usr/bin/env bash
# Самопроверка стенда ИЗНУТРИ гостя: порты, страницы, артефакты. Не атака.
set -uo pipefail
FAIL=0
ok()  { echo "  [OK] $*"; }
bad() { echo "  [FAIL] $*"; FAIL=1; }

echo "== порты =="
ss -tln 2>/dev/null | grep -q ':22 ' && ok "22/ssh слушается" || bad "22 закрыт"
ss -tln 2>/dev/null | grep -q ':80 ' && ok "80/http слушается" || bad "80 закрыт"

echo "== веб =="
code() { curl -s -o /dev/null -w "%{http_code}" ${2:+ -H "$2"} "http://127.0.0.1$1"; }
[ "$(code /)" = "200" ] && ok "GET / → 200" || bad "GET / не 200"
[ "$(code /robots.txt)" = "200" ] && ok "robots.txt → 200" || bad "robots.txt"
[ "$(code /login.php)" = "200" ] && ok "login.php → 200" || bad "login.php"
[ "$(code /backup/site-backup.zip)" = "200" ] && ok "backup zip → 200" || bad "backup zip"
[ "$(code / 'Host: dev.planbox.htb')" = "200" ] && ok "vhost dev.planbox.htb → 200" || bad "dev vhost"

echo "== артефакты =="
[ -f /home/student/user.txt ] && ok "user.txt" || bad "user.txt"
[ -f /root/root.txt ] && ok "root.txt" || bad "root.txt"
sudo -l -U student 2>/dev/null | grep -q 'NOPASSWD.*find' && ok "sudo find" || bad "sudo-правило"
[ -f /etc/cron.d/planbox-backup ] && ok "cron" || bad "cron"

[ "$FAIL" -eq 0 ] && echo "СТЕНД ГОТОВ" || echo "ЕСТЬ ПРОБЕЛЫ"
exit "$FAIL"
