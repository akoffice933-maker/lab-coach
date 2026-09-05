#!/usr/bin/env bash
# Каркас сессии на ТВОЕЙ Kali: только локальная подготовка (каталоги, scope-напоминалка).
# Цель — твой стенд. Чужие IP сюда не подставлять.
set -euo pipefail
TARGET="${1:-192.168.56.110}"
D="$HOME/HTB/planbox"
mkdir -p "$D"/{nmap,loot,exploits,www}
cat > "$D/scope.txt" <<EOF
SCOPE: только $TARGET (мой учебный стенд planbox).
Подсети, чужие IP, интернет — запрещены.
EOF
TPL="$(dirname "$0")/notes-template.md"
if [ -f "$TPL" ] && [ ! -f "$D/notes.md" ]; then
  sed "s/ЦЕЛЬ/$TARGET/g" "$TPL" > "$D/notes.md"
fi
echo "Каталог: $D"
echo
echo "Шаг 0:  ping -c3 $TARGET"
echo "        echo \"$TARGET planbox.htb\" | sudo tee -a /etc/hosts"
echo "Шаг 1:  nmap -p- --min-rate 2000 -T4 $TARGET -oN $D/nmap/allports.txt"
echo "        nmap -p <PORTS> -sC -sV $TARGET -oN $D/nmap/services.txt"
echo "        ffuf -w subdomains.txt -u http://planbox.htb -H 'Host: FUZZ.planbox.htb'"
echo "        gobuster dir -u http://planbox.htb -w common.txt -x php,txt,bak,zip"
echo "Coach:  lab-coach scan $TARGET   (профиль custom, CIDR 192.168.56.0/24)"
echo "Дальше — по plan.txt. Удачи."
