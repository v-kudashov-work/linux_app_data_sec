#!/bin/bash
# install_app_data_sec.sh - Полная установка/обновление app_data_sec и watchdog для ALT Linux

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
BACKUP_DIR="/root/app_data_sec_backup"

# Флаг обновления
IS_UPDATE=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   APP DATA SEC - INSTALL/UPDATE${NC}"
echo -e "${BLUE}          for ALT Linux${NC}"
echo -e "${BLUE}========================================${NC}\n"

# ============================================================================
# ПРОВЕРКА ПРАВ
# ============================================================================

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# ============================================================================
# ПРОВЕРКА, УСТАНОВЛЕН ЛИ МОДУЛЬ
# ============================================================================

if [ -f "$INSTALL_PATH/app_data_sec_loader" ] || [ -f "$BPF_OBJ_PATH/app_data_sec.bpf.o" ]; then
    IS_UPDATE=1
    echo -e "${YELLOW}[INFO]${NC} Existing installation detected!"
    echo -e "${BLUE}[INFO]${NC} This will update the module (services will be stopped and restarted)"
    echo ""
    read -p "Continue with update? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[INFO]${NC} Update cancelled"
        exit 0
    fi
    echo ""
fi

# ============================================================================
# ОСТАНОВКА СЕРВИСОВ (при обновлении)
# ============================================================================

if [ "$IS_UPDATE" -eq 1 ]; then
    echo -e "\n${BLUE}[INFO]${NC} Stopping services for update..."

    # Создаем бэкап
    mkdir -p "$BACKUP_DIR"
    if [ -f "$CONFIG_PATH" ]; then
        cp "$CONFIG_PATH" "$BACKUP_DIR/app_data_sec.conf.backup"
        echo -e "${GREEN}[OK]${NC} Config backed up to: $BACKUP_DIR/app_data_sec.conf.backup"
    fi
    if [ -f "$BPF_OBJ_PATH/app_data_sec.bpf.o" ]; then
        cp "$BPF_OBJ_PATH/app_data_sec.bpf.o" "$BACKUP_DIR/app_data_sec.bpf.o.backup"
    fi
    if [ -f "$INSTALL_PATH/app_data_sec_loader" ]; then
        cp "$INSTALL_PATH/app_data_sec_loader" "$BACKUP_DIR/app_data_sec_loader.backup"
    fi
    if [ -f "$INSTALL_PATH/app_data_sec_watchdog" ]; then
        cp "$INSTALL_PATH/app_data_sec_watchdog" "$BACKUP_DIR/app_data_sec_watchdog.backup"
    fi

    # Останавливаем сервисы
    systemctl stop app_data_sec_loader 2>/dev/null || true
    systemctl stop app_data_sec_watchdog 2>/dev/null || true

    # Ждем завершения
    sleep 2

    # Убиваем процессы если остались
    pkill -f app_data_sec_loader 2>/dev/null || true
    pkill -f app_data_sec_watchdog 2>/dev/null || true

    echo -e "${GREEN}[OK]${NC} Services stopped"
fi

# ============================================================================
# ОПРЕДЕЛЕНИЕ ДИСТРИБУТИВА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Detecting distribution..."

if [ -f "/etc/altlinux-release" ] || grep -q "ALT" /etc/os-release 2>/dev/null; then
    echo -e "${GREEN}[OK]${NC} ALT Linux detected"
    PKG_MANAGER="apt-get"
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -qq"
    IS_ALT=1
elif [ -f "/etc/debian_version" ] || grep -q "Debian" /etc/os-release 2>/dev/null; then
    echo -e "${GREEN}[OK]${NC} Debian/Ubuntu detected"
    PKG_MANAGER="apt-get"
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -qq"
    IS_ALT=0
elif [ -f "/etc/redhat-release" ] || grep -q "Red Hat" /etc/os-release 2>/dev/null; then
    echo -e "${GREEN}[OK]${NC} RHEL/CentOS/Fedora detected"
    PKG_MANAGER="dnf"
    PKG_INSTALL="dnf install -y"
    PKG_UPDATE="dnf check-update -q"
    IS_ALT=0
else
    echo -e "${YELLOW}[WARNING]${NC} Unknown distribution, assuming Debian/ALT compatible"
    PKG_MANAGER="apt-get"
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -qq"
    IS_ALT=0
fi

# ============================================================================
# ПРОВЕРКА ЗАВИСИМОСТЕЙ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking dependencies..."

# Функция проверки и установки пакета
check_package() {
    local pkg=$1
    if ! command -v $pkg &> /dev/null; then
        echo -e "${YELLOW}[WARNING]${NC} $pkg not found. Installing..."
        $PKG_UPDATE 2>/dev/null || true
        $PKG_INSTALL $pkg 2>/dev/null || true
    fi
}

if [ "$IS_ALT" -eq 1 ]; then
    # ALT Linux специфичные имена пакетов
    echo -e "${BLUE}[INFO]${NC} Installing ALT Linux packages..."
    $PKG_UPDATE 2>/dev/null || true

    # Базовые пакеты
    $PKG_INSTALL gcc clang make pkg-config 2>/dev/null || true

    # BPF пакеты
    $PKG_INSTALL libbpf-devel libelf-devel zlib-devel 2>/dev/null || true

    # Ядерные заголовки
    $PKG_INSTALL kernel-headers-modules-std-def 2>/dev/null || true
    $PKG_INSTALL kernel-headers-modules-un-def 2>/dev/null || true

    # BPF инструменты
    $PKG_INSTALL bpftool 2>/dev/null || true
else
    # Стандартные имена для Debian/Ubuntu
    check_package build-essential
    check_package clang
    check_package pkg-config
    check_package libbpf-dev
    check_package libelf-dev
    check_package zlib1g-dev

    # BPF инструменты
    if ! command -v bpftool &> /dev/null; then
        $PKG_INSTALL linux-tools-common linux-tools-$(uname -r) 2>/dev/null || true
        $PKG_INSTALL bpftool 2>/dev/null || true
    fi
fi

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
    if [ "$IS_ALT" -eq 1 ]; then
        echo -e "${YELLOW}[INFO]${NC} For ALT Linux, try: modprobe -v btf"
        echo -e "${YELLOW}[INFO]${NC} Or install kernel with CONFIG_DEBUG_INFO_BTF=y"
    fi
fi

# Проверка LSM
if [ -f "/sys/kernel/security/lsm" ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    if echo "$LSM" | grep -q "bpf"; then
        echo -e "${GREEN}[OK]${NC} BPF LSM enabled: $LSM"
    else
        echo -e "${YELLOW}[WARNING]${NC} BPF LSM not found in: $LSM"
        echo -e "${YELLOW}[INFO]${NC} To enable, add 'bpf' to lsm= in /etc/default/grub"
        echo -e "${YELLOW}[INFO]${NC} Example: GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=lockdown,capability,integrity,bpf\""
    fi
fi

# Проверка CONFIG_BPF_LSM
if [ -f "/proc/config.gz" ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_LSM=y"; then
        echo -e "${GREEN}[OK]${NC} CONFIG_BPF_LSM=y"
    else
        echo -e "${YELLOW}[WARNING]${NC} CONFIG_BPF_LSM may not be enabled"
    fi
fi

# ============================================================================
# ПОИСК BPF ЗАГОЛОВКОВ ДЛЯ ALT LINUX
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Setting up BPF include paths..."

BPF_INCLUDE_DIRS=""
BPF_EXTRA_FLAGS=""

if [ "$IS_ALT" -eq 1 ]; then
    echo -e "${BLUE}[INFO]${NC} Searching for BPF headers in ALT Linux..."

    # Список путей для поиска bpf_helpers.h
    ALT_BPF_PATHS=(
        "/usr/include/bpf"
        "/usr/src/kernel-headers/include/bpf"
        "/usr/src/kernel-headers-modules-std-def/include/bpf"
        "/usr/src/kernel-headers-modules-un-def/include/bpf"
        "/usr/lib/modules/$(uname -r)/build/include/bpf"
        "/usr/src/linux-headers-$(uname -r)/include/bpf"
    )

    for path in "${ALT_BPF_PATHS[@]}"; do
        if [ -f "$path/bpf_helpers.h" ]; then
            BPF_INCLUDE_DIRS="$BPF_INCLUDE_DIRS -I$path"
            echo -e "${GREEN}[OK]${NC} Found BPF headers in: $path"
        fi
    done

    # Если не нашли, пробуем через find
    if [ -z "$BPF_INCLUDE_DIRS" ]; then
        echo -e "${YELLOW}[WARNING]${NC} bpf_helpers.h not found in standard locations"
        echo -e "${YELLOW}[INFO]${NC} Trying to find via find..."

        FOUND_PATH=$(find /usr -name "bpf_helpers.h" 2>/dev/null | head -1)
        if [ -n "$FOUND_PATH" ]; then
            FOUND_DIR=$(dirname "$FOUND_PATH")
            BPF_INCLUDE_DIRS="-I$FOUND_DIR"
            echo -e "${GREEN}[OK]${NC} Found BPF headers in: $FOUND_DIR"
        else
            echo -e "${YELLOW}[WARNING]${NC} bpf_helpers.h not found!"
            echo -e "${YELLOW}[INFO]${NC} Try installing: apt-get install libbpf-devel kernel-headers-modules-std-def"
            echo -e "${YELLOW}[INFO]${NC} Continuing with fallback paths..."

            # Fallback пути
            if [ -d "/usr/include/bpf" ]; then
                BPF_INCLUDE_DIRS="-I/usr/include/bpf"
            elif [ -d "/usr/src/kernel-headers/include/bpf" ]; then
                BPF_INCLUDE_DIRS="-I/usr/src/kernel-headers/include/bpf"
            else
                BPF_INCLUDE_DIRS="-I/usr/include"
            fi
        fi
    fi

    # Добавляем дополнительные пути для ALT
    BPF_INCLUDE_DIRS="$BPF_INCLUDE_DIRS -I/usr/include"
    BPF_EXTRA_FLAGS="-D__TARGET_ARCH_x86"
else
    # Стандартные пути для Debian/Ubuntu
    BPF_INCLUDE_DIRS="-I/usr/include/bpf -I/usr/include"
    BPF_EXTRA_FLAGS="-D__TARGET_ARCH_x86"
fi

echo -e "${BLUE}[INFO]${NC} BPF include paths: $BPF_INCLUDE_DIRS"

# ============================================================================
# ГЕНЕРАЦИЯ VMLINUX.H
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Generating vmlinux.h..."

if [ ! -f "vmlinux.h" ]; then
    if command -v bpftool &> /dev/null; then
        if [ -f "/sys/kernel/btf/vmlinux" ]; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null
            if [ -f "vmlinux.h" ]; then
                echo -e "${GREEN}[OK]${NC} vmlinux.h generated from BTF"
            fi
        fi
    fi

    # Если не удалось сгенерировать, создаем минимальную версию
    if [ ! -f "vmlinux.h" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Failed to generate vmlinux.h from BTF, creating minimal version..."
        cat > vmlinux.h << 'EOF'
#ifndef __VMLINUX_H
#define __VMLINUX_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

#define __always_inline inline __attribute__((always_inline))
#define __attribute_const__ __attribute__((__const__))

typedef unsigned long long __ino_t;
typedef unsigned int __mode_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned int __dev_t;
typedef unsigned long long __nlink_t;
typedef long long __off_t;

struct stat {
    __dev_t st_dev;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    __off_t st_size;
    long st_blksize;
    long st_blocks;
    long st_atime;
    long st_mtime;
    long st_ctime;
};

#endif
EOF
        echo -e "${GREEN}[OK]${NC} Minimal vmlinux.h created"
    fi
else
    echo -e "${GREEN}[OK]${NC} vmlinux.h already exists"
fi

# ============================================================================
# КОМПИЛЯЦИЯ BPF
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building BPF program..."

if [ ! -f "app_data_sec.bpf.c" ]; then
    echo -e "${RED}[ERROR]${NC} app_data_sec.bpf.c not found!"
    exit 1
fi

# Компиляция BPF
echo -e "${BLUE}[INFO]${NC} Compiling BPF program..."
echo -e "${BLUE}[INFO]${NC} Include paths: $BPF_INCLUDE_DIRS"

clang -g -O2 -target bpf \
    $BPF_INCLUDE_DIRS \
    $BPF_EXTRA_FLAGS \
    -I. \
    -c app_data_sec.bpf.c -o app_data_sec.bpf.o 2>&1

if [ ! -f "app_data_sec.bpf.o" ]; then
    echo -e "${RED}[ERROR]${NC} BPF compilation failed!"
    echo -e "${YELLOW}[INFO]${NC} Try installing: apt-get install libbpf-devel kernel-headers-modules-std-def"
    echo -e "${YELLOW}[INFO]${NC} Or check that bpf_helpers.h is available"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} BPF compiled"

# ============================================================================
# КОМПИЛЯЦИЯ APP_DATA_SEC_LOADER
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_loader..."

if [ ! -f "app_data_sec_loader.c" ]; then
    echo -e "${RED}[ERROR]${NC} app_data_sec_loader.c not found!"
    exit 1
fi

# Компиляция загрузчика
echo -e "${BLUE}[INFO]${NC} Compiling loader..."

gcc -Wall -O2 -o app_data_sec_loader app_data_sec_loader.c -lbpf -lelf -lz 2>&1

if [ ! -f "app_data_sec_loader" ]; then
    echo -e "${RED}[ERROR]${NC} Loader compilation failed!"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Loader compiled"

# ============================================================================
# КОМПИЛЯЦИЯ MERGE_CONFIG
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_merge_config..."

# Ищем файл в текущей директории и в поддиректории merge_config/
MERGE_SRC=""
if [ -f "app_data_sec_merge_config.c" ]; then
    MERGE_SRC="app_data_sec_merge_config.c"
elif [ -f "merge_config/app_data_sec_merge_config.c" ]; then
    MERGE_SRC="merge_config/app_data_sec_merge_config.c"
elif [ -f "./merge_config/app_data_sec_merge_config.c" ]; then
    MERGE_SRC="./merge_config/app_data_sec_merge_config.c"
else
    # Пробуем найти через find
    MERGE_SRC=$(find . -name "app_data_sec_merge_config.c" -type f 2>/dev/null | head -1)
fi

if [ -n "$MERGE_SRC" ] && [ -f "$MERGE_SRC" ]; then
    echo -e "${BLUE}[INFO]${NC} Found: $MERGE_SRC"
    echo -e "${BLUE}[INFO]${NC} Compiling merge_config..."
    gcc -Wall -O2 -o app_data_sec_merge_config "$MERGE_SRC" 2>&1

    if [ -f "app_data_sec_merge_config" ]; then
        echo -e "${GREEN}[OK]${NC} Merge_config compiled"
    else
        echo -e "${RED}[ERROR]${NC} Merge_config compilation failed!"
        # Не прерываем установку, т.к. это вспомогательная утилита
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} app_data_sec_merge_config.c not found, skipping"
fi

# ============================================================================
# КОМПИЛЯЦИЯ UNPROTECT
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_unprotect..."

# Ищем файл unprotect
UNPROTECT_SRC=""
if [ -f "app_data_sec_unprotect.c" ]; then
    UNPROTECT_SRC="app_data_sec_unprotect.c"
elif [ -f "unprotect/app_data_sec_unprotect.c" ]; then
    UNPROTECT_SRC="unprotect/app_data_sec_unprotect.c"
else
    UNPROTECT_SRC=$(find . -name "app_data_sec_unprotect.c" -type f 2>/dev/null | head -1)
fi

if [ -n "$UNPROTECT_SRC" ] && [ -f "$UNPROTECT_SRC" ]; then
    echo -e "${BLUE}[INFO]${NC} Found: $UNPROTECT_SRC"
    echo -e "${BLUE}[INFO]${NC} Compiling unprotect..."
    gcc -Wall -O2 -o app_data_sec_unprotect "$UNPROTECT_SRC" 2>&1

    if [ -f "app_data_sec_unprotect" ]; then
        echo -e "${GREEN}[OK]${NC} Unprotect compiled"
    else
        echo -e "${RED}[ERROR]${NC} Unprotect compilation failed!"
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} app_data_sec_unprotect.c not found, skipping"
fi

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
    echo -e "${YELLOW}[WARNING]${NC} Watchdog source not found, skipping"
    WATCHDOG_SRC=""
fi

if [ -n "$WATCHDOG_SRC" ]; then
    gcc -Wall -O2 -o app_data_sec_watchdog "$WATCHDOG_SRC" -lm 2>&1

    if [ ! -f "app_data_sec_watchdog" ]; then
        echo -e "${RED}[ERROR]${NC} Watchdog compilation failed!"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Watchdog compiled"
else
    echo -e "${YELLOW}[WARNING]${NC} Watchdog not compiled"
fi

# ============================================================================
# УСТАНОВКА ФАЙЛОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Installing files..."

# Создаём директории
mkdir -p "$INSTALL_PATH"
mkdir -p "$BPF_OBJ_PATH"
mkdir -p "$LOG_PATH"

# Устанавливаем app_data_sec_loader
cp -f app_data_sec_loader "$INSTALL_PATH/"
chmod 755 "$INSTALL_PATH/app_data_sec_loader"
echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_loader"

# Устанавливаем merge_config
if [ -f "app_data_sec_merge_config" ]; then
    cp -f app_data_sec_merge_config "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/app_data_sec_merge_config"
    echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_merge_config"
fi

# Устанавливаем unprotect
if [ -f "app_data_sec_unprotect" ]; then
    cp -f app_data_sec_unprotect "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/app_data_sec_unprotect"
    echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_unprotect"
fi

# Устанавливаем watchdog
if [ -f "app_data_sec_watchdog" ]; then
    cp -f app_data_sec_watchdog "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/app_data_sec_watchdog"
    echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_watchdog"
fi

# Устанавливаем BPF объект
cp -f app_data_sec.bpf.o "$BPF_OBJ_PATH/"
chmod 644 "$BPF_OBJ_PATH/app_data_sec.bpf.o"
echo -e "${GREEN}[OK]${NC} Installed: $BPF_OBJ_PATH/app_data_sec.bpf.o"

# Создаём символические ссылки
ln -sf "$INSTALL_PATH/app_data_sec_loader" /usr/bin/app_data_sec_loader 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_loader"

if [ -f "$INSTALL_PATH/app_data_sec_merge_config" ]; then
    ln -sf "$INSTALL_PATH/app_data_sec_merge_config" /usr/bin/app_data_sec_merge_config 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_merge_config"
fi

if [ -f "$INSTALL_PATH/app_data_sec_unprotect" ]; then
    ln -sf "$INSTALL_PATH/app_data_sec_unprotect" /usr/bin/app_data_sec_unprotect 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_unprotect"
fi

if [ -f "$INSTALL_PATH/app_data_sec_watchdog" ]; then
    ln -sf "$INSTALL_PATH/app_data_sec_watchdog" /usr/bin/app_data_sec_watchdog 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_watchdog"
fi

# ============================================================================
# КОНФИГУРАЦИЯ (только при новой установке или если нет конфига)
# ============================================================================

if [ ! -f "$CONFIG_PATH" ]; then
    echo -e "\n${BLUE}[INFO]${NC} Creating configuration..."
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
    echo -e "\n${YELLOW}[INFO]${NC} Config already exists, keeping existing"
    if [ "$IS_UPDATE" -eq 1 ]; then
        echo -e "${YELLOW}[INFO]${NC} To merge new entries, use: app_data_sec_merge_config <new.conf>"
    fi
fi

# ============================================================================
# ЛОГ-ФАЙЛЫ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating log files..."

for logfile in app_data_sec_loader.log app_data_sec_loader_error.log \
               app_data_sec_watchdog.log app_data_sec_watchdog_error.log; do
    touch "$LOG_PATH/$logfile"
    chmod 644 "$LOG_PATH/$logfile"
done

echo -e "${GREEN}[OK]${NC} Log files created"

# ============================================================================
# СОЗДАНИЕ/ОБНОВЛЕНИЕ СЕРВИСОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating/updating systemd services..."

# ============================================================================
# СЕРВИС APP_DATA_SEC_LOADER
# ============================================================================

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
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_loader.service"

# ============================================================================
# СЕРВИС APP_DATA_SEC_WATCHDOG
# ============================================================================

cat > "$SERVICE_DIR/app_data_sec_watchdog.service" << 'EOF'
[Unit]
Description=APP DATA SEC Watchdog Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target
Wants=app_data_sec_loader.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/app_data_sec_watchdog
ExecStop=/bin/kill -SIGTERM $MAINPID
ExecReload=/bin/kill -SIGHUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=append:/var/log/app_data_sec_watchdog.log
StandardError=append:/var/log/app_data_sec_watchdog_error.log
SyslogIdentifier=app_data_sec_watchdog
PIDFile=/run/app_data_sec_watchdog.pid

# Права для работы с файлами на рабочих столах
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
ReadWritePaths=/ /var/log /home /tmp /root

CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_watchdog.service"

# ============================================================================
# ЗАПУСК СЕРВИСОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Starting services..."

systemctl daemon-reload

# Запускаем loader
systemctl enable app_data_sec_loader 2>/dev/null || true
systemctl restart app_data_sec_loader

# Запускаем watchdog
if [ -f "$INSTALL_PATH/app_data_sec_watchdog" ]; then
    systemctl enable app_data_sec_watchdog 2>/dev/null || true
    systemctl restart app_data_sec_watchdog
fi

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
# ПРОВЕРКА BPF
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking BPF programs..."

if command -v bpftool &> /dev/null; then
    BPF_PROGS=$(bpftool prog list 2>/dev/null | grep -c "block_" || echo "0")
    echo -e "  BPF programs loaded: $BPF_PROGS"

    # Проверяем карты
    echo -e "\n${BLUE}[INFO]${NC} BPF maps:"
    bpftool map list 2>/dev/null | grep -E "(folder_config|folder_allowed|folder_scripts)" || echo "  No maps found"
else
    echo -e "  ${YELLOW}bpftool not available${NC}"
fi

# ============================================================================
# ВЫВОД ИНФОРМАЦИИ
# ============================================================================

if [ "$IS_UPDATE" -eq 1 ]; then
    UPDATE_MSG="Update"
else
    UPDATE_MSG="Installation"
fi

cat << EOF

${GREEN}✅ $UPDATE_MSG completed successfully!${NC}

${BLUE}Installed files:${NC}
  $INSTALL_PATH/app_data_sec_loader
  $INSTALL_PATH/app_data_sec_merge_config
  $INSTALL_PATH/app_data_sec_unprotect
  $INSTALL_PATH/app_data_sec_watchdog
  $BPF_OBJ_PATH/app_data_sec.bpf.o
  $CONFIG_PATH

${BLUE}Services:${NC}
  app_data_sec_loader   - Main protection service
  app_data_sec_watchdog - Watchdog service (creates desktop file on errors)

${BLUE}Watchdog:${NC}
  When app_data_sec_loader stops, watchdog creates:
  app_data_sec_errors.txt on each user's desktop

${BLUE}Commands:${NC}
  sudo systemctl status app_data_sec_loader
  sudo systemctl status app_data_sec_watchdog
  sudo journalctl -u app_data_sec_loader -f
  sudo journalctl -u app_data_sec_watchdog -f

${BLUE}Configuration:${NC}
  Edit: sudo nano $CONFIG_PATH
  Reload: sudo systemctl restart app_data_sec_loader

${BLUE}Merge config:${NC}
  app_data_sec_merge_config /tmp/new.conf
  app_data_sec_merge_config -m /etc/app_data_sec.conf /tmp/new.conf

${BLUE}Remove protection:${NC}
  app_data_sec_unprotect /tmp/remove.conf
  app_data_sec_unprotect -c /etc/app_data_sec.conf /tmp/remove.conf
  app_data_sec_unprotect -l

EOF

if [ "$IS_UPDATE" -eq 1 ]; then
    echo -e "${YELLOW}[INFO]${NC} Backup saved to: $BACKUP_DIR"
    echo -e "${YELLOW}[INFO]${NC} To restore: sudo cp $BACKUP_DIR/app_data_sec.conf.backup $CONFIG_PATH"
    echo ""
fi

echo -e "${BLUE}Troubleshooting ALT Linux:${NC}"
echo "  1. Check kernel support: bpftool feature"
echo "  2. Check LSM: cat /sys/kernel/security/lsm"
echo "  3. For BPF LSM: add 'bpf' to lsm= in /etc/default/grub"
echo "  4. Check BPF headers: find /usr -name \"bpf_helpers.h\""
echo "  5. Install packages: apt-get install libbpf-devel kernel-headers-modules-std-def"
echo ""
echo -e "${BLUE}Watchdog desktop file:${NC}"
echo "  If error occurs, file appears on desktop: app_data_sec_errors.txt"
echo "  User can delete it after reading"

if [ "$IS_UPDATE" -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}[INFO]${NC} If you experience issues after update:"
    echo "  1. Check logs: sudo journalctl -u app_data_sec_loader -f"
    echo "  2. Restart: sudo systemctl restart app_data_sec_loader"
    echo "  3. Restore backup: sudo cp $BACKUP_DIR/app_data_sec_loader.backup $INSTALL_PATH/"
fi

echo -e "\n${GREEN}Done!${NC}"
