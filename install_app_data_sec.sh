#!/bin/bash
# install_app_data_sec.sh - Полная установка app_data_sec и watchdog

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Конфигурация
INSTALL_PATH="/usr/local/bin"
CONFIG_PATH="/etc/app_data_sec.conf"
BPF_OBJ_PATH="/usr/local/lib/app_data_sec"
LOG_PATH="/var/log"
SERVICE_DIR="/etc/systemd/system"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   APP DATA SEC - FULL INSTALL${NC}"
echo -e "${BLUE}========================================${NC}\n"

# ============================================================================
# ПРОВЕРКА ПРАВ
# ============================================================================

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# ============================================================================
# ПРОВЕРКА ЗАВИСИМОСТЕЙ
# ============================================================================

echo -e "${BLUE}[INFO]${NC} Checking dependencies..."

# Функция проверки и установки пакета
check_package() {
    local pkg=$1
    if ! command -v $pkg &> /dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} $pkg not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y $pkg 2>/dev/null || true
    fi
}

# Проверка компиляторов
check_package build-essential
check_package clang
check_package pkg-config

# Проверка BPF инструментов
if ! command -v bpftool &> /dev/null; then
    echo -e "${YELLOW}[WARNING]${NC} bpftool not found. Installing..."
    apt-get update -qq 2>/dev/null || true
    apt-get install -y linux-tools-common linux-tools-$(uname -r) 2>/dev/null || true

    # Если bpftool всё ещё не установлен, пробуем из репозитория
    if ! command -v bpftool &> /dev/null; then
        apt-get install -y bpftool 2>/dev/null || true
    fi
fi

# Проверка библиотек
check_package libbpf-dev
check_package libelf-dev
check_package zlib1g-dev
check_package zenity

echo -e "${GREEN}[OK]${NC} Dependencies OK"

# ============================================================================
# ПРОВЕРКА КОНФИГУРАЦИИ ЯДРА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking kernel configuration..."

# Проверка BTF
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    echo -e "${GREEN}[OK]${NC} BTF found"
else
    echo -e "${YELLOW}[WARNING]${NC} BTF not found. Kernel may not support CO-RE"
fi

# Проверка LSM
if [ -f "/sys/kernel/security/lsm" ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    if echo "$LSM" | grep -q "bpf"; then
        echo -e "${GREEN}[OK]${NC} BPF LSM enabled: $LSM"
    else
        echo -e "${YELLOW}[WARNING]${NC} BPF LSM not found in: $LSM"
        echo -e "${YELLOW}[INFO]${NC} To enable, add 'bpf' to lsm= in /etc/default/grub"
    fi
fi

# ============================================================================
# КОМПИЛЯЦИЯ BPF
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building BPF program..."

if [ ! -f "app_data_sec.bpf.c" ]; then
    echo -e "${RED}[ERROR]${NC} app_data_sec.bpf.c not found!"
    exit 1
fi

# Генерация vmlinux.h если нет
if [ ! -f "vmlinux.h" ]; then
    echo -e "${BLUE}[INFO]${NC} Generating vmlinux.h..."
    if command -v bpftool &> /dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || {
            echo -e "${YELLOW}[WARNING]${NC} Failed to generate vmlinux.h"
        }
    fi
fi

# Компиляция BPF
echo -e "${BLUE}[INFO]${NC} Compiling BPF program..."
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c app_data_sec.bpf.c -o app_data_sec.bpf.o 2>&1

if [ ! -f "app_data_sec.bpf.o" ]; then
    echo -e "${RED}[ERROR]${NC} BPF compilation failed!"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} BPF compiled"

# Генерация скелета
if command -v bpftool &> /dev/null; then
    echo -e "${BLUE}[INFO]${NC} Generating BPF skeleton..."
    bpftool gen skeleton app_data_sec.bpf.o > app_data_sec.skel.h 2>/dev/null
    if [ -f "app_data_sec.skel.h" ]; then
        echo -e "${GREEN}[OK]${NC} Skeleton generated"
    fi
fi

# ============================================================================
# КОМПИЛЯЦИЯ APP_DATA_SEC_LOADER
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_loader..."

if [ ! -f "app_data_sec_loader.c" ]; then
    echo -e "${RED}[ERROR]${NC} app_data_sec_loader.c not found!"
    exit 1
fi

# Компиляция загрузчика
gcc -Wall -O2 -o app_data_sec_loader app_data_sec_loader.c -lbpf -lelf -lz 2>&1

if [ ! -f "app_data_sec_loader" ]; then
    echo -e "${RED}[ERROR]${NC} Loader compilation failed!"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Loader compiled"

# ============================================================================
# КОМПИЛЯЦИЯ WATCHDOG
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building watchdog..."

# Поиск исходника watchdog
WATCHDOG_SRC=""
if [ -f "app_data_sec_watchdog_zenity.c" ]; then
    WATCHDOG_SRC="app_data_sec_watchdog_zenity.c"
elif [ -f "app_data_sec_watchdog.c" ]; then
    WATCHDOG_SRC="app_data_sec_watchdog.c"
else
    echo -e "${RED}[ERROR]${NC} Watchdog source not found!"
    exit 1
fi

# Компиляция
gcc -Wall -O2 -o app_data_sec_watchdog "$WATCHDOG_SRC" -lm 2>&1

if [ ! -f "app_data_sec_watchdog" ]; then
    echo -e "${RED}[ERROR]${NC} Watchdog compilation failed!"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Watchdog compiled"

# ============================================================================
# УСТАНОВКА ФАЙЛОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Installing files..."

# Создаём директории
mkdir -p "$INSTALL_PATH"
mkdir -p "$BPF_OBJ_PATH"
mkdir -p "$LOG_PATH"

# Устанавливаем app_data_sec_loader
cp app_data_sec_loader "$INSTALL_PATH/"
chmod 755 "$INSTALL_PATH/app_data_sec_loader"
echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_loader"

# Устанавливаем watchdog
cp app_data_sec_watchdog "$INSTALL_PATH/"
chmod 755 "$INSTALL_PATH/app_data_sec_watchdog"
echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_watchdog"

# Устанавливаем BPF объект
cp app_data_sec.bpf.o "$BPF_OBJ_PATH/"
chmod 644 "$BPF_OBJ_PATH/app_data_sec.bpf.o"
echo -e "${GREEN}[OK]${NC} Installed: $BPF_OBJ_PATH/app_data_sec.bpf.o"

# Копируем скелет (опционально)
if [ -f "app_data_sec.skel.h" ]; then
    cp app_data_sec.skel.h "$BPF_OBJ_PATH/"
    echo -e "${GREEN}[OK]${NC} Installed: $BPF_OBJ_PATH/app_data_sec.skel.h"
fi

# Создаём символическую ссылку
ln -sf "$INSTALL_PATH/app_data_sec_loader" /usr/bin/app_data_sec_loader 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_loader"

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating configuration..."

if [ ! -f "$CONFIG_PATH" ]; then
    cat > "$CONFIG_PATH" << 'EOF'
# /etc/app_data_sec.conf
# Конфигурация для eBPF блокировщика доступа к папкам
#
# enable = yes|no - включает или отключает все ограничения
# protect <path> [allowed_prog1] [allowed_prog2] ... - защищает папку
#   path - путь к папке (можно использовать ~ для домашней директории)
#   allowed_prog - абсолютный путь к программе, которая может обходить защиту

enable = yes

# Примеры:
# protect /home/user/.test_app /bin/konsole
# protect ~/.secret_folder /bin/my_app
EOF
    echo -e "${GREEN}[OK]${NC} Created: $CONFIG_PATH"
else
    echo -e "${YELLOW}[WARNING]${NC} Config already exists, keeping existing"
fi

# ============================================================================
# ЛОГ-ФАЙЛЫ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating log files..."

touch "$LOG_PATH/app_data_sec_loader.log"
touch "$LOG_PATH/app_data_sec_loader_error.log"
touch "$LOG_PATH/app_data_sec_watchdog.log"
touch "$LOG_PATH/app_data_sec_watchdog_error.log"
chmod 644 "$LOG_PATH/app_data_sec_loader.log"
chmod 644 "$LOG_PATH/app_data_sec_loader_error.log"
chmod 644 "$LOG_PATH/app_data_sec_watchdog.log"
chmod 644 "$LOG_PATH/app_data_sec_watchdog_error.log"

echo -e "${GREEN}[OK]${NC} Log files created"

# ============================================================================
# СОЗДАНИЕ СЕРВИСОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating systemd services..."

# Определяем DISPLAY
DISPLAY_VAR=":0"
if [ -n "$DISPLAY" ]; then
    DISPLAY_VAR="$DISPLAY"
elif command -v who &> /dev/null; then
    DISPLAY_VAR=$(who 2>/dev/null | grep -E "\(:[0-9]+\)" | head -1 | sed -E 's/.*\((:[0-9]+)\)$/\1/' || echo ":0")
fi

# Сервис для app_data_sec_loader
cat > "$SERVICE_DIR/app_data_sec_loader.service" << 'EOF'
[Unit]
Description=APP DATA SEC Loader Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/app_data_sec_loader -l 2
ExecStop=/bin/kill -SIGTERM $MAINPID
ExecReload=/bin/kill -SIGHUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=append:/var/log/app_data_sec_loader.log
StandardError=append:/var/log/app_data_sec_loader_error.log
SyslogIdentifier=app_data_sec_loader
PIDFile=/run/app_data_sec_loader.pid

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/log
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_loader.service"

# Сервис для watchdog
cat > "$SERVICE_DIR/app_data_sec_watchdog.service" << EOF
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
Environment=XAUTHORITY=/root/.Xauthority
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
echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_watchdog.service"

# ============================================================================
# НАСТРОЙКА XAUTHORITY (для GUI)
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Setting up Xauthority..."

mkdir -p /run/user/0
chmod 700 /run/user/0

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
# ЗАПУСК СЕРВИСОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Starting services..."

systemctl daemon-reload

# Запускаем loader
systemctl enable app_data_sec_loader 2>/dev/null || true
systemctl restart app_data_sec_loader

# Запускаем watchdog
systemctl enable app_data_sec_watchdog 2>/dev/null || true
systemctl restart app_data_sec_watchdog

sleep 3

# ============================================================================
# ПРОВЕРКА СТАТУСА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Service status:"

echo ""
echo -e "${BLUE}app_data_sec_loader:${NC}"
systemctl status app_data_sec_loader --no-pager || true

echo ""
echo -e "${BLUE}app_data_sec_watchdog:${NC}"
systemctl status app_data_sec_watchdog --no-pager || true

# ============================================================================
# ПРОВЕРКА ЛОГОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Recent logs:"

echo ""
echo -e "${BLUE}app_data_sec_loader logs:${NC}"
journalctl -u app_data_sec_loader -n 5 --no-pager 2>/dev/null || echo "  No logs yet"

echo ""
echo -e "${BLUE}app_data_sec_watchdog logs:${NC}"
journalctl -u app_data_sec_watchdog -n 5 --no-pager 2>/dev/null || echo "  No logs yet"

# ============================================================================
# ВЫВОД ИНФОРМАЦИИ
# ============================================================================

cat << EOF

${GREEN}✅ Installation completed successfully!${NC}

${BLUE}Installed files:${NC}
  $INSTALL_PATH/app_data_sec_loader
  $INSTALL_PATH/app_data_sec_watchdog
  $BPF_OBJ_PATH/app_data_sec.bpf.o
  $CONFIG_PATH

${BLUE}Services:${NC}
  app_data_sec_loader   - Main protection service
  app_data_sec_watchdog - Watchdog service

${BLUE}Commands:${NC}
  sudo systemctl status app_data_sec_loader
  sudo systemctl status app_data_sec_watchdog
  sudo journalctl -u app_data_sec_loader -f
  sudo journalctl -u app_data_sec_watchdog -f
  sudo tail -f /var/log/app_data_sec_loader.log

${BLUE}Configuration:${NC}
  Edit: sudo nano $CONFIG_PATH
  Reload: sudo systemctl restart app_data_sec_loader

${BLUE}Uninstall:${NC}
  sudo ./uninstall_app_data_sec.sh

EOF

echo -e "${GREEN}Done!${NC}"
