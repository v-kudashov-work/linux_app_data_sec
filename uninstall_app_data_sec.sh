#!/bin/bash
# uninstall_app_data_sec.sh - Полное удаление app_data_sec

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   APP DATA SEC - UNINSTALL${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Проверка прав
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# Подтверждение
echo -e "${YELLOW}[WARNING]${NC} This will remove:"
echo "  - app_data_sec_loader"
echo "  - app_data_sec_merge_config"
echo "  - app_data_sec_unprotect"
echo "  - app_data_sec_watchdog"
echo "  - app_data_sec_messages_to_syslog"
echo "  - app_data_sec_autoconfig"
echo "  - BPF objects (app_data_sec.bpf.o)"
echo "  - Systemd services"
echo "  - Log files"
echo "  - Desktop error files (optional)"
echo "  - Configuration (optional)"
echo ""
read -p "Are you sure you want to continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[INFO]${NC} Uninstall cancelled"
    exit 0
fi

# ============================================================================
# ОСТАНОВКА СЕРВИСОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Stopping services..."

systemctl stop app_data_sec_loader 2>/dev/null || true
systemctl stop app_data_sec_watchdog 2>/dev/null || true
systemctl stop app_data_sec_autoconfig 2>/dev/null || true
systemctl disable app_data_sec_loader 2>/dev/null || true
systemctl disable app_data_sec_watchdog 2>/dev/null || true
systemctl disable app_data_sec_autoconfig 2>/dev/null || true

systemctl stop app_data_sec_messages 2>/dev/null || true
systemctl disable app_data_sec_messages 2>/dev/null || true
pkill -f app_data_sec_messages_to_syslog 2>/dev/null || true

# Убиваем процессы если остались
pkill -f app_data_sec_loader 2>/dev/null || true
pkill -f app_data_sec_watchdog 2>/dev/null || true
pkill -f app_data_sec_autoconfig 2>/dev/null || true

echo -e "${GREEN}[OK]${NC} Services stopped"

# ============================================================================
# УДАЛЕНИЕ ФАЙЛОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Removing files..."

# Бинарники
rm -f /usr/local/bin/app_data_sec_loader
rm -f /usr/local/bin/app_data_sec_merge_config
rm -f /usr/local/bin/app_data_sec_unprotect
rm -f /usr/local/bin/app_data_sec_watchdog
rm -f /usr/local/bin/app_data_sec_autoconfig
rm -f /usr/bin/app_data_sec_loader 2>/dev/null || true
rm -f /usr/bin/app_data_sec_merge_config 2>/dev/null || true
rm -f /usr/bin/app_data_sec_unprotect 2>/dev/null || true
rm -f /usr/bin/app_data_sec_watchdog 2>/dev/null || true
rm -f /usr/bin/app_data_sec_autoconfig 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Removed binaries"

# BPF объекты
rm -f /usr/local/lib/app_data_sec/app_data_sec.bpf.o
rm -f /usr/local/lib/app_data_sec/app_data_sec.skel.h
rmdir /usr/local/lib/app_data_sec 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Removed BPF objects"

# Сервисы
rm -f /etc/systemd/system/app_data_sec_loader.service
rm -f /etc/systemd/system/app_data_sec_watchdog.service
rm -f /etc/systemd/system/app_data_sec_autoconfig.service
echo -e "${GREEN}[OK]${NC} Removed service files"

# Логи
rm -f /var/log/app_data_sec_loader.log
rm -f /var/log/app_data_sec_loader_error.log
rm -f /var/log/app_data_sec_watchdog.log
rm -f /var/log/app_data_sec_autoconfig.log
rm -f /var/log/app_data_sec_watchdog_error.log
echo -e "${GREEN}[OK]${NC} Removed log files"

# PID файлы
rm -f /run/app_data_sec_loader.pid
rm -f /run/app_data_sec_watchdog.pid
rm -f /run/app_data_sec_autoconfig.pid
echo -e "${GREEN}[OK]${NC} Removed PID files"

# Lock файлы
rm -f /var/lock/app_data_sec_watchdog.lock
echo -e "${GREEN}[OK]${NC} Removed lock files"

# app_data_sec_messages_to_syslog
rm -f /usr/local/bin/app_data_sec_messages_to_syslog
rm -f /usr/bin/app_data_sec_messages_to_syslog 2>/dev/null || true
rm -f /etc/systemd/system/app_data_sec_messages.service
rm -f /var/log/app_data_sec_messages.log
rm -f /var/log/app_data_sec_messages_error.log
echo -e "${GREEN}[OK]${NC} Removed app_data_sec_messages_to_syslog files"

# ============================================================================
# КОНФИГУРАЦИЯ (опционально)
# ============================================================================

echo ""
read -p "Remove configuration file /etc/app_data_sec.conf? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f /etc/app_data_sec.conf
    rm -f /etc/app_data_sec.conf.bak 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Removed configuration"
else
    echo -e "${YELLOW}[INFO]${NC} Keeping configuration: /etc/app_data_sec.conf"
fi

# ============================================================================
# УДАЛЕНИЕ ПАПКИ С КОНФИГАМИ
# ============================================================================

rm -rf /etc/app_data_sec.d/
echo -e "${GREEN}[OK]${NC} Removed configurations directory: /etc/app_data_sec.d/"

# ============================================================================
# ДЕСКТОПНЫЕ ФАЙЛЫ (опционально)
# ============================================================================

echo ""
echo -e "${YELLOW}[INFO]${NC} Desktop error files may remain on user desktops."
echo "These files are: app_data_sec_errors.txt"
echo ""
read -p "Remove desktop error files from all users? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[INFO]${NC} Removing desktop error files..."

    # Находим все домашние директории пользователей
    for home in /home/* /root; do
        if [ -d "$home" ]; then
            # Ищем desktop директории
            for desktop in "$home/Desktop" "$home/Рабочий стол" "$home/Рабочий стол"; do
                if [ -d "$desktop" ]; then
                    rm -f "$desktop/app_data_sec_errors.txt"
                    if [ -f "$desktop/app_data_sec_errors.txt" ]; then
                        echo -e "  Removed: $desktop/app_data_sec_errors.txt"
                    fi
                fi
            done
        fi
    done
    echo -e "${GREEN}[OK]${NC} Removed desktop error files"
else
    echo -e "${YELLOW}[INFO]${NC} Desktop files kept"
    echo -e "${YELLOW}[INFO]${NC} To remove manually: rm ~/Desktop/app_data_sec_errors.txt"
fi

# ============================================================================
# XAUTHORITY (опционально)
# ============================================================================

echo ""
read -p "Remove Xauthority file /run/user/0/Xauthority? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f /run/user/0/Xauthority
    rmdir /run/user/0 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Removed Xauthority"
fi

# ============================================================================
# ОЧИСТКА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Reloading systemd..."
systemctl daemon-reload

# ============================================================================
# ПРОВЕРКА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking remaining files..."

REMAINING=$(find /usr/local/bin /usr/bin /usr/local/lib /etc/systemd/system /var/log /run -name "*app_data_sec*" 2>/dev/null | grep -v "\.conf" || echo "")

if [ -n "$REMAINING" ]; then
    echo -e "${YELLOW}[WARNING]${NC} Some files still remain:"
    echo "$REMAINING"
    echo ""
    read -p "Remove remaining files? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "$REMAINING" | while read -r file; do
            rm -f "$file" 2>/dev/null || true
            echo -e "${GREEN}[OK]${NC} Removed: $file"
        done
    fi
else
    echo -e "${GREEN}[OK]${NC} No remaining files found"
fi

# ============================================================================
# ВЫВОД
# ============================================================================

cat << EOF

${GREEN}✅ Uninstall completed successfully!${NC}

${BLUE}Removed:${NC}
  - app_data_sec_loader binary
  - app_data_sec_merge_config binary
  - app_data_sec_unprotect binary
  - app_data_sec_watchdog binary
  - app_data_sec_messages_to_syslog binary
  - app_data_sec_autoconfig binary
  - BPF objects (app_data_sec.bpf.o)
  - Systemd services
  - Log files
  - PID files
  - Lock files

${YELLOW}To verify:${NC}
  systemctl status app_data_sec_loader 2>/dev/null || echo "  Service not found"
  systemctl status app_data_sec_watchdog 2>/dev/null || echo "  Service not found"
  systemctl status app_data_sec_autoconfig 2>/dev/null || echo "  Service not found"
  ls -la /usr/local/bin/app_data_sec* 2>/dev/null || echo "  Binaries removed"
  ls -la /usr/local/lib/app_data_sec 2>/dev/null || echo "  BPF objects removed"

EOF

echo -e "${GREEN}Done!${NC}"
