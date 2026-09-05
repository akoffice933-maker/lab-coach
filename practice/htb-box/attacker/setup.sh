#!/usr/bin/env bash
# Настройка атакующей Kali под шаги plan.txt. Идемпотентен: можно запускать повторно.
# Ручные добивки после: searchsploit -u ; nuclei -update-templates
set -euo pipefail

PKGS=(openvpn nmap ffuf gobuster seclists exploitdb nuclei
      python3-venv python3-pip git curl unzip)

echo "[*] apt..."
sudo apt-get update -qq
for p in "${PKGS[@]}"; do
  sudo apt-get install -y -qq "$p" >/dev/null 2>&1 && echo "  [OK] $p" || echo "  [WARN] не встал: $p (доставь вручную)"
done

echo "[*] каталоги..."
mkdir -p ~/HTB ~/vpn ~/wordlists

echo "[*] Lab Coach..."
if [ -f ~/lab-coach/pyproject.toml ]; then
  [ -d ~/lab-coach/.venv ] || python3 -m venv ~/lab-coach/.venv
  # shellcheck disable=SC1091
  source ~/lab-coach/.venv/bin/activate
  pip -q install -e "$HOME/lab-coach[dev]" 2>/dev/null || pip -q install -e "$HOME/lab-coach" || echo "  [WARN] pip install не удался"
  echo "  [OK] venv: ~/lab-coach/.venv"
else
  echo "  [..] ~/lab-coach нет — скопируй проект и повтори setup.sh"
fi

echo "[*] алиасы..."
grep -q "alias htb=" ~/.bashrc 2>/dev/null || echo "alias htb='cd ~/HTB'" >> ~/.bashrc

echo "[*] словари:"
ls -d /usr/share/seclists /usr/share/wordlists 2>/dev/null || echo "  [WARN] словарей нет"
echo "[DONE] Дальше вручную: searchsploit -u ; nuclei -update-templates ; .ovpn в ~/vpn"
