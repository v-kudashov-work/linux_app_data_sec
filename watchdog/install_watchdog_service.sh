#!/bin/bash
# install_watchdog_service.sh - Полная установка watchdog с сервисом

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   APP DATA SEC - INSTALL WATCHDOG${NC}"
echo -e "${BLUE}         (with service & GUI)${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Проверка прав
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# ============================================================================
# КОМПИЛЯЦИЯ
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Compiling watchdog..."

# Проверяем наличие исходника
if [ ! -f "app_data_sec_watchdog_zenity.c" ]; then
    echo -e "${RED}[ERROR]${NC} Source file app_data_sec_watchdog_zenity.c not found!"
    exit 1
fi

# Компилируем
gcc -Wall -O2 -o app_data_sec_watchdog app_data_sec_watchdog_zenity.c -lm 2>&1

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Compilation failed!"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Watchdog compiled"

# ============================================================================
# УСТАНОВКА БИНАРНИКА
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Installing binary..."

mkdir -p /usr/local/bin
cp app_data_sec_watchdog /usr/local/bin/
chmod 755 /usr/local/bin/app_data_sec_watchdog

echo -e "${GREEN}[OK]${NC} Installed to /usr/local/bin/app_data_sec_watchdog"

# ============================================================================
# ОПРЕДЕЛЕНИЕ DISPLAY
# ============================================================================

# Определяем DISPLAY
DISPLAY_VAR=":0"
if [ -n "$DISPLAY" ]; then
    DISPLAY_VAR="$DISPLAY"
elif command -v who &> /dev/null; then
    DISPLAY_VAR=$(who 2>/dev/null | grep -E "\(:[0-9]+\)" | head -1 | sed -E 's/.*\((:[0-9]+)\)$/\1/' || echo ":0")
fi

echo -e "${BLUE}[INFO]${NC} Using DISPLAY: $DISPLAY_VAR"

# ============================================================================
# НАСТРОЙКА XAUTHORITY
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Setting up Xauthority..."

mkdir -p /run/user/0
chmod 700 /run/user/0

# Ищем Xauthority
XAUTH_FILE=""
for f in /root/.Xauthority /home/*/.Xauthority /tmp/.Xauthority; do
    if [ -f "$f" ]; then
        XAUTH_FILE="$f"
        break
    fi
done

if [ -n "$XAUTH_FILE" ]; then
    cp "$XAUTH_FILE" /run/user/0/Xauthority 2>/dev/null || true
    chmod 600 /run/user/0/Xauthority 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Xauthority set up"
else
    echo -e "${YELLOW}[WARNING]${NC} No Xauthority file found. GUI dialogs may not work."
fi

# ============================================================================
# СОЗДАНИЕ СЕРВИСА
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/app_data_sec_watchdog.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=APP DATA SEC Watchdog Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target graphical.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
Environment=DISPLAY=$DISPLAY_VAR
Environment=XAUTHORITY=/run/user/0/Xauthority
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus
ExecStart=/usr/local/bin/app_data_sec_watchdog -z -i 10
ExecStop=/bin/kill -SIGTERM \$MAINPID
ExecReload=/bin/kill -SIGHUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:/var/log/app_data_sec_watchdog.log
StandardError=append:/var/log/app_data_sec_watchdog_error.log
SyslogIdentifier=app_data_sec_watchdog
PIDFile=/run/app_data_sec_watchdog.pid

# Сняты ограничения для GUI
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
ReadWritePaths=/ /var/log /tmp /run/user/0 /home
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID

[Install]
WantedBy=multi-user.target graphical.target
EOF

echo -e "${GREEN}[OK]${NC} Service file created: $SERVICE_FILE"

# ============================================================================
# СОЗДАНИЕ ЛОГОВ
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Creating log files..."

touch /var/log/app_data_sec_watchdog.log
touch /var/log/app_data_sec_watchdog_error.log
chmod 644 /var/log/app_data_sec_watchdog.log
chmod 644 /var/log/app_data_sec_watchdog_error.log

echo -e "${GREEN}[OK]${NC} Log files created"

# ============================================================================
# ЗАПУСК СЕРВИСА
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Reloading systemd..."
systemctl daemon-reload

echo -e "${BLUE}[INFO]${NC} Enabling service..."
systemctl enable app_data_sec_watchdog.service 2>/dev/null || true

echo -e "${BLUE}[INFO]${NC} Starting service..."
systemctl restart app_data_sec_watchdog.service

sleep 2

# ============================================================================
# ПРОВЕРКА СТАТУСА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Service status:"
systemctl status app_data_sec_watchdog.service --no-pager || true

echo -e "\n${BLUE}[INFO]${NC} Last log entries:"
journalctl -u app_data_sec_watchdog.service -n 10 --no-pager 2>/dev/null || true

# ============================================================================
# ВЫВОД ИНФОРМАЦИИ
# ============================================================================

cat << EOF

${GREEN}✅ Watchdog installed successfully!${NC}

${BLUE}Commands:${NC}
  sudo systemctl start app_data_sec_watchdog     - Start
  sudo systemctl stop app_data_sec_watchdog      - Stop
  sudo systemctl restart app_data_sec_watchdog   - Restart
  sudo systemctl status app_data_sec_watchdog    - Status
  sudo systemctl enable app_data_sec_watchdog    - Enable on boot
  sudo systemctl disable app_data_sec_watchdog   - Disable on boot

${BLUE}Logs:${NC}
  sudo journalctl -u app_data_sec_watchdog -f
  sudo tail -f /var/log/app_data_sec_watchdog.log

${BLUE}Manual run (for testing):${NC}
  sudo app_data_sec_watchdog -z -i 10

${BLUE}Uninstall:${NC}
  sudo systemctl stop app_data_sec_watchdog
  sudo systemctl disable app_data_sec_watchdog
  sudo rm -f $SERVICE_FILE
  sudo rm -f /usr/local/bin/app_data_sec_watchdog
  sudo systemctl daemon-reload

EOF

echo -e "${GREEN}Installation completed!${NC}"
