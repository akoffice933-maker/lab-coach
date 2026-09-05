#!/usr/bin/env bash
# PlanBox builder. Запуск ОДИН раз от root внутри гостя (Vagrant provision или вручную).
# Создаёт НАМЕРЕННЫЕ учебные мис конфиги. Машина должна жить только в host-only.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

LAB_USER="student"
LAB_PASS="LabPractice2026!"
WEBROOT="/var/www/planbox"

echo "[*] пакеты..."
apt-get update -qq
apt-get install -y -qq openssh-server apache2 php libapache2-mod-php zip unzip cron >/dev/null
systemctl enable --now ssh apache2 cron

echo "[*] пользователь $LAB_USER..."
id "$LAB_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$LAB_USER"
echo "$LAB_USER:$LAB_PASS" | chpasswd
echo "PLANBOX{u53r_fl4g_l4b_0nly}" > "/home/$LAB_USER/user.txt"
chown "$LAB_USER:$LAB_USER" "/home/$LAB_USER/user.txt"
chmod 640 "/home/$LAB_USER/user.txt"
echo "PLANBOX{r00t_fl4g_l4b_0nly}" > /root/root.txt
chmod 600 /root/root.txt

echo "[*] веб-приложение..."
mkdir -p "$WEBROOT/backup" /var/www/dev
cat > "$WEBROOT/index.php" <<'PHP_EOF'
<html><head><title>PlanBox staging</title></head><body>
<h1>PlanBox — staging</h1>
<p><a href="login.php">Вход</a> | <a href="view.php?page=welcome.php">Доки</a></p>
</body></html>
PHP_EOF
cat > "$WEBROOT/login.php" <<'PHP_EOF'
<?php
$VALID_USER = 'student';
$VALID_PASS = 'LabPractice2026!';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $u = $_POST['user'] ?? ''; $p = $_POST['pass'] ?? '';
  if ($u === $VALID_USER && $p === $VALID_PASS) {
    echo '<h1>PlanBox dashboard</h1><p>Добро пожаловать, student.</p>';
    echo '<p>SSH-доступ: <b>student@planbox.htb</b>, пароль тот же, что и здесь (reuse в учебных целях).</p>';
    exit;
  }
  $msg = 'Неверная пара.';
}
?>
<html><body><h1>Вход</h1><p style="color:red"><?php echo htmlspecialchars($msg); ?></p>
<form method="post">user: <input name="user"><br>pass: <input type="password" name="pass"><br>
<input type="submit" value="Войти"></form></body></html>
PHP_EOF
cat > "$WEBROOT/view.php" <<'PHP_EOF'
<?php
// Учебный LFI-артефакт: параметр без валидации (намеренно).
$page = $_GET['page'] ?? '';
if ($page === '') { echo '<a href="view.php?page=welcome.php">welcome</a>'; exit; }
include($page);
PHP_EOF
echo "<?php echo 'PlanBox docs v0.3-staging'; " > "$WEBROOT/welcome.php"
cat > "$WEBROOT/config.php" <<'PHP_EOF'
<?php // deploy config (учебный артефакт, пароль reused)
$db_user = 'planbox';
$db_pass = 'LabPractice2026!';
PHP_EOF
cat > "$WEBROOT/robots.txt" <<'EOF'
User-agent: *
Disallow: /backup/
Disallow: /dev/
EOF
cat > "$WEBROOT/backup/deploy-notes.txt" <<EOF
PlanBox staging deploy notes:
- web login: student / $LAB_PASS
- TODO: rotate before prod, remove test account
EOF
cp "$WEBROOT/config.php" "$WEBROOT/backup/config.php"
cp "$WEBROOT/backup/deploy-notes.txt" "$WEBROOT/backup/" 2>/dev/null || true
(cd "$WEBROOT/backup" && zip -q -j site-backup.zip deploy-notes.txt config.php)
cat > /var/www/dev/index.html <<'EOF'
<html><body><h1>dev.planbox.htb — staging notes</h1>
<p>Админка переехала на основной сайт. Тестовый аккаунт <b>student</b> удалить до прода.</p>
</body></html>
EOF
cat > /var/www/dev/info.php <<'EOF'
<?php phpinfo();
EOF
chown -R www-data:www-data "$WEBROOT" /var/www/dev

echo "[*] vhosts (000 — основной/default, 001 — dev для ffuf)..."
cat > /etc/apache2/sites-available/000-planbox.conf <<EOF
<VirtualHost *:80>
    ServerName planbox.htb
    DocumentRoot $WEBROOT
</VirtualHost>
EOF
cat > /etc/apache2/sites-available/001-dev.conf <<'EOF'
<VirtualHost *:80>
    ServerName dev.planbox.htb
    DocumentRoot /var/www/dev
</VirtualHost>
EOF
a2dissite 000-default >/dev/null 2>&1 || true
a2ensite 000-planbox 001-dev >/dev/null
systemctl reload apache2

echo "[*] privesc-артефакты (намеренные)..."
echo "$LAB_USER ALL=(ALL) NOPASSWD: /usr/bin/find" > /etc/sudoers.d/student
chmod 440 /etc/sudoers.d/student
cat > /usr/local/bin/planbox-backup.sh <<'EOF'
#!/bin/bash
# Учебный артефакт: world-writable скрипт, выполняемый cron от root (намеренно).
date >> /var/log/planbox-backup.log
EOF
chmod 777 /usr/local/bin/planbox-backup.sh
echo "*/2 * * * * root /usr/local/bin/planbox-backup.sh" > /etc/cron.d/planbox-backup
chmod 644 /etc/cron.d/planbox-backup

echo "[*] проверка..."
bash "$(dirname "$0")/verify.sh"
echo "[DONE] PlanBox готов. IP: 192.168.56.110 (planbox.htb)"
