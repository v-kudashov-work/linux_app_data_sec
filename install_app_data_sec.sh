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
CONFIGS_DIR="/etc/app_data_sec.d/configs"
BPF_OBJ_PATH="/usr/local/lib/app_data_sec"
LOG_PATH="/var/log"
SERVICE_DIR="/etc/systemd/system"
BACKUP_DIR="/root/app_data_sec_backup"
CONFIG_SOURCE_DIR="./configs"  # Папка с предустановленными конфигами
CONFIG_SOURCE_DIR="./configs"                      # Папка с предустановленными конфигами
AUTOCONFIG_DIR="/etc/app_data_sec.autoconfig"      # Папка для автоматического импорта конфигов

# Флаг обновления
IS_UPDATE=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   APP DATA SEC - INSTALL/UPDATE${NC}"
echo -e "${BLUE}          for ALT Linux / Ubuntu${NC}"
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

    # Создаём бэкап
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
    if [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
        cp "$INSTALL_PATH/app_data_sec_messages_to_syslog" "$BACKUP_DIR/app_data_sec_messages_to_syslog.backup"
    fi
    if [ -f "$INSTALL_PATH/app_data_sec_autoconfig" ]; then
        cp "$INSTALL_PATH/app_data_sec_autoconfig" "$BACKUP_DIR/app_data_sec_autoconfig.backup"
    fi

    # Останавливаем сервисы
    systemctl stop app_data_sec_loader 2>/dev/null || true
    systemctl stop app_data_sec_watchdog 2>/dev/null || true
    systemctl stop app_data_sec_messages 2>/dev/null || true
    systemctl stop app_data_sec_autoconfig 2>/dev/null || true

    # Ждём завершения
    sleep 2

    # Убиваем процессы если остались
    pkill -f app_data_sec_loader 2>/dev/null || true
    pkill -f app_data_sec_watchdog 2>/dev/null || true
    pkill -f app_data_sec_messages_to_syslog 2>/dev/null || true
    pkill -f app_data_sec_autoconfig 2>/dev/null || true

    echo -e "${GREEN}[OK]${NC} Services stopped"
fi

# ============================================================================
# ФУНКЦИЯ ПОИСКА КОНФИГОВ ПРИЛОЖЕНИЙ
# ============================================================================

find_app_configs() {
    local configs_found=()
    local configs_desc=()

    if [ ! -d "$CONFIG_SOURCE_DIR" ]; then
        return 1
    fi

    # Ищем все .conf файлы в папке configs
    local idx=0
    for config_file in "$CONFIG_SOURCE_DIR"/*.conf; do
        if [ -f "$config_file" ]; then
            local basename=$(basename "$config_file" .conf)

            # Пытаемся прочитать описание из комментария в файле
            local description=""
            if head -20 "$config_file" 2>/dev/null | grep -q "^#.*Description:"; then
                description=$(head -20 "$config_file" | grep "^#.*Description:" | sed 's/^#.*Description:[[:space:]]*//' | head -1)
            else
                # Если описания нет, используем имя файла
                description="$basename"
            fi

            configs_found[$idx]="$config_file"
            configs_desc[$idx]="$description"
            ((idx++))
        fi
    done

    if [ $idx -eq 0 ]; then
        return 1
    fi

    # Выводим найденные конфиги
    echo -e "\n${BLUE}[INFO]${NC} Found application configurations in $CONFIG_SOURCE_DIR/:"
    for ((i=0; i<idx; i++)); do
        local filename=$(basename "${configs_found[$i]}")
        printf "  %2d) %-30s - %s\n" $((i+1)) "$filename" "${configs_desc[$i]}"
    done
    echo ""

    # Возвращаем массивы через глобальные переменные
    CONFIGS_FOUND=("${configs_found[@]}")
    CONFIGS_DESC=("${configs_desc[@]}")
    CONFIGS_COUNT=$idx

    return 0
}

# ============================================================================
# ФУНКЦИЯ ВЫБОРА КОНФИГОВ
# ============================================================================

select_app_configs() {
    echo -e "${YELLOW}[QUESTION]${NC} Install pre-configured protections for known applications?"
    echo "  (Configuration files from ./configs/ directory)"
    echo ""
    echo "  This will add protection rules for common applications like:"
    echo "  - Browser profiles (Firefox, Chrome, etc.)"
    echo "  - Email clients (Thunderbird, etc.)"
    echo "  - And more..."
    echo ""
    read -p "Install application configurations? (y/N) " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[INFO]${NC} Skipping application configurations"
        SELECTED_CONFIGS=()
        return 1
    fi

    echo -e "\n${BLUE}[INFO]${NC} Available configurations:"
    echo "  0) Install ALL configurations"
    echo ""

    # Получаем список конфигов
    local configs_found=()
    local configs_desc=()
    local idx=0

    for config_file in "$CONFIG_SOURCE_DIR"/*.conf; do
        if [ -f "$config_file" ]; then
            local basename=$(basename "$config_file" .conf)
            local description=""

            if head -20 "$config_file" 2>/dev/null | grep -q "^#.*Description:"; then
                description=$(head -20 "$config_file" | grep "^#.*Description:" | sed 's/^#.*Description:[[:space:]]*//' | head -1)
            else
                description="$basename"
            fi

            configs_found[$idx]="$config_file"
            configs_desc[$idx]="$description"
            printf "  %2d) %-30s - %s\n" $((idx+1)) "$basename" "$description"
            ((idx++))
        fi
    done

    if [ $idx -eq 0 ]; then
        echo -e "${YELLOW}[WARNING]${NC} No configuration files found in $CONFIG_SOURCE_DIR/"
        SELECTED_CONFIGS=()
        return 1
    fi

    echo ""
    echo -e "${YELLOW}[INFO]${NC} Enter numbers separated by spaces (e.g., '1 3 5')"
    echo "  Or press Enter to skip all"
    echo ""
    read -p "Select configurations to install: " selection

    # Если пользователь ничего не ввёл
    if [ -z "$selection" ]; then
        echo -e "${BLUE}[INFO]${NC} No configurations selected"
        SELECTED_CONFIGS=()
        return 1
    fi

    # Очищаем ввод от пробелов
    local clean_selection=$(echo "$selection" | tr -d '[:space:]')

    # Проверяем, не выбрал ли пользователь "0" (все конфиги)
    if [ "$clean_selection" = "0" ]; then
        SELECTED_CONFIGS=("${configs_found[@]}")
        echo -e "${GREEN}[OK]${NC} All configurations selected (${#SELECTED_CONFIGS[@]} files)"
        return 0
    fi

    # Обрабатываем выбор (уже без "0")
    SELECTED_CONFIGS=()

    for num in $selection; do
        # Убираем пробелы и ведущие нули
        num=$(echo "$num" | tr -d '[:space:]' | sed 's/^0*//')

        # Пропускаем пустые значения
        [ -z "$num" ] && continue

        # Пропускаем "0" (уже обработано выше)
        [ "$num" = "0" ] && continue

        # Проверяем, что это число
        if ! [[ "$num" =~ ^[0-9]+$ ]]; then
            echo -e "${YELLOW}[WARNING]${NC} Invalid input: $num (not a number, skipped)"
            continue
        fi

        if [ "$num" -ge 1 ] 2>/dev/null && [ "$num" -le "$idx" ] 2>/dev/null; then
            local idx_num=$((num-1))
            SELECTED_CONFIGS+=("${configs_found[$idx_num]}")
        else
            echo -e "${YELLOW}[WARNING]${NC} Invalid selection: $num (must be between 1 and $idx, skipped)"
        fi
    done

    # Проверяем, есть ли выбранные конфиги
    if [ ${#SELECTED_CONFIGS[@]} -eq 0 ]; then
        echo -e "${BLUE}[INFO]${NC} No configurations selected"
        SELECTED_CONFIGS=()
        return 1
    fi

    echo -e "\n${GREEN}[OK]${NC} Selected configurations (${#SELECTED_CONFIGS[@]} files):"
    for config in "${SELECTED_CONFIGS[@]}"; do
        echo "  - $(basename "$config")"
    done

    return 0
}

# ============================================================================
# ФУНКЦИЯ ИМПОРТА КОНФИГОВ
# ============================================================================

import_selected_configs() {
    local merge_cmd="$INSTALL_PATH/app_data_sec_merge_config"

    if [ ! -f "$merge_cmd" ]; then
        echo -e "${YELLOW}[WARNING]${NC} merge_config not found, skipping import"
        return 1
    fi

    if [ ${#SELECTED_CONFIGS[@]} -eq 0 ]; then
        return 0
    fi

    echo -e "\n${BLUE}[INFO]${NC} Importing selected configurations..."

    # Создаём временную директорию для всех выбранных конфигов
    local temp_dir=$(mktemp -d)

    # Копируем выбранные конфиги во временную папку
    for config in "${SELECTED_CONFIGS[@]}"; do
        cp "$config" "$temp_dir/"
        echo -e "  - Copied: $(basename "$config")"
    done

    # Запускаем merge_config с временной папкой
    echo -e "\n${BLUE}[INFO]${NC} Running merge_config to import configurations..."

    if "$merge_cmd" -m "$CONFIG_PATH" "$temp_dir/"; then
        echo -e "${GREEN}[OK]${NC} Configurations imported successfully"

        # Если merge_config создал бэкап основного конфига, показываем
        if [ -f "${CONFIG_PATH}.bak" ]; then
            echo -e "${YELLOW}[INFO]${NC} Backup created: ${CONFIG_PATH}.bak"
        fi

        # Создаём папку для конфигов, если её нет
        mkdir -p "$CONFIGS_DIR"

        # Копируем выбранные конфиги в /etc/app_data_sec.d/ для справки
        for config in "${SELECTED_CONFIGS[@]}"; do
            local basename=$(basename "$config")
            cp "$config" "$CONFIGS_DIR/$basename"
            echo -e "  - Saved: $CONFIGS_DIR/$basename"
        done

        # Удаляем временную папку
        rm -rf "$temp_dir"

        echo -e "${GREEN}[OK]${NC} Configuration import completed"
        echo -e "${YELLOW}[INFO]${NC} To apply changes: sudo systemctl restart app_data_sec_loader"
        return 0
    else
        echo -e "${RED}[ERROR]${NC} Failed to import configurations"
        rm -rf "$temp_dir"
        return 1
    fi
}

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
# НАСТРОЙКА BPF LSM В GRUB
# ============================================================================

configure_bpf_lsm() {
    echo -e "\n${BLUE}[INFO]${NC} Checking BPF LSM configuration..."

    # Проверяем текущий LSM
    if [ ! -f "/sys/kernel/security/lsm" ]; then
        echo -e "${YELLOW}[WARNING]${NC} /sys/kernel/security/lsm not found"
        return 1
    fi

    CURRENT_LSM=$(cat /sys/kernel/security/lsm)

    # Проверяем, есть ли уже bpf
    if echo "$CURRENT_LSM" | grep -q "bpf"; then
        echo -e "${GREEN}[OK]${NC} BPF LSM already enabled: $CURRENT_LSM"
        return 0
    fi

    echo -e "${YELLOW}[WARNING]${NC} BPF LSM not enabled"
    echo -e "${YELLOW}[INFO]${NC} Current LSM: $CURRENT_LSM"
    echo ""
    echo -e "${BLUE}To enable BPF LSM, add 'bpf' to the lsm= parameter.${NC}"
    echo -e "${BLUE}This requires editing GRUB and rebooting.${NC}"
    echo -e "${BLUE}Please restart the installation after the reboot.${NC}"
    echo ""

    read -p "Configure BPF LSM now? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}[INFO]${NC} Skipping GRUB configuration"
        echo -e "${YELLOW}[INFO]${NC} Manual steps:"
        echo "  1. sudo nano /etc/default/grub"
        echo "  2. Add 'bpf' to lsm= (preserve existing modules)"
        echo "  3. sudo update-grub && sudo reboot"
        return 0
    fi

    # Проверяем GRUB
    if [ ! -f "/etc/default/grub" ]; then
        echo -e "${RED}[ERROR]${NC} /etc/default/grub not found"
        return 1
    fi

    # Создаём бэкап
    BACKUP_DIR="/root/app_data_sec_backup"
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/grub_default.$(date +%Y%m%d_%H%M%S).backup"

    echo -e "${BLUE}[INFO]${NC} Creating backup: $BACKUP_FILE"
    cp /etc/default/grub "$BACKUP_FILE" || {
        echo -e "${RED}[ERROR]${NC} Failed to create backup"
        return 1
    }
    echo -e "${GREEN}[OK]${NC} Backup created"

    # Находим строку с GRUB_CMDLINE_LINUX_DEFAULT
    if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
        CURRENT_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/\1/')

        # Проверяем, есть ли lsm=
        if echo "$CURRENT_CMDLINE" | grep -q "lsm="; then
            # lsm= есть, добавляем bpf если его нет
            if echo "$CURRENT_CMDLINE" | grep -q "lsm=.*bpf"; then
                echo -e "${GREEN}[OK]${NC} bpf already in lsm= (should not happen)"
                return 0
            fi

            # Добавляем bpf в конец существующего списка lsm=
            echo -e "${BLUE}[INFO]${NC} Adding bpf to existing lsm=..."

            # Проверяем, что lsm= не заканчивается на запятую
            if echo "$CURRENT_CMDLINE" | grep -q "lsm=.*,$"; then
                # Уже есть запятая в конце
                NEW_CMDLINE=$(echo "$CURRENT_CMDLINE" | sed 's/lsm=\([^ ]*\)/lsm=\1bpf/')
            else
                # Добавляем запятую и bpf
                NEW_CMDLINE=$(echo "$CURRENT_CMDLINE" | sed 's/lsm=\([^ ]*\)/lsm=\1,bpf/')
            fi
        else
            # lsm= нет, добавляем только bpf (без других модулей)
            echo -e "${BLUE}[INFO]${NC} Adding lsm=bpf..."
            NEW_CMDLINE="$CURRENT_CMDLINE lsm=bpf"
        fi

        # Обновляем GRUB
        sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$NEW_CMDLINE\"/" /etc/default/grub

    else
        # GRUB_CMDLINE_LINUX_DEFAULT нет, создаём с lsm=bpf
        echo -e "${BLUE}[INFO]${NC} Creating GRUB_CMDLINE_LINUX_DEFAULT with lsm=bpf..."
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=bpf"' >> /etc/default/grub
    fi

    # Показываем изменения
    echo -e "\n${BLUE}[INFO]${NC} New GRUB configuration:"
    grep "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub
    echo ""

    # Обновляем GRUB
    echo -e "${BLUE}[INFO]${NC} Updating GRUB..."
    if command -v update-grub &> /dev/null; then
        if update-grub; then
            echo -e "${GREEN}[OK]${NC} GRUB updated"
        else
            echo -e "${RED}[ERROR]${NC} Failed to update GRUB"
            echo -e "${YELLOW}[INFO]${NC} Restoring backup..."
            cp "$BACKUP_FILE" /etc/default/grub
            return 1
        fi
    elif command -v grub2-mkconfig &> /dev/null; then
        if grub2-mkconfig -o /boot/grub2/grub.cfg; then
            echo -e "${GREEN}[OK]${NC} GRUB updated"
        else
            echo -e "${RED}[ERROR]${NC} Failed to update GRUB"
            cp "$BACKUP_FILE" /etc/default/grub
            return 1
        fi
    else
        echo -e "${YELLOW}[WARNING]${NC} update-grub not found, please update manually"
    fi

    echo -e "\n${GREEN}[OK]${NC} BPF LSM configured"
    echo -e "${YELLOW}[INFO]${NC} Reboot required for changes to take effect"
    echo ""

    read -p "Please restart the installation after the reboot. Reboot now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[INFO]${NC} Rebooting in 5 seconds..."
        sleep 5
        reboot
    else
        echo -e "${YELLOW}[INFO]${NC} Please reboot manually when ready"
    fi

    return 0
}


# ============================================================================
# ПРОВЕРКА И НАСТРОЙКА BPF LSM
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking BPF LSM configuration..."

# Проверяем, нужно ли настраивать
if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q "bpf"; then
    echo -e "${YELLOW}[WARNING]${NC} BPF LSM not enabled"
    echo -e "${YELLOW}[INFO]${NC} This is REQUIRED for eBPF programs to work"
    echo ""

    # Спрашиваем пользователя
    read -p "Configure BPF LSM in GRUB now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        configure_bpf_lsm
        # Если была настроена и требуется перезагрузка, инсталляция продолжится после reboot
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[OK]${NC} BPF LSM configured"
        fi
    else
        echo -e "${YELLOW}[INFO]${NC} Skipping BPF LSM configuration"
        echo -e "${YELLOW}[WARNING]${NC} app_data_sec will NOT work without BPF LSM!"
        echo -e "${YELLOW}[INFO]${NC} You can configure manually later:"
        echo "  sudo nano /etc/default/grub"
        echo "  Add: lsm=bpf"
        echo "  Then: sudo update-grub && sudo reboot"
        echo ""
        read -p "Continue with installation anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[INFO]${NC} Installation cancelled"
            exit 0
        fi
    fi
else
    echo -e "${GREEN}[OK]${NC} BPF LSM already enabled"
fi

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
    -mllvm -bpf-stack-size=1024 \
    -I. \
    -Wno-missing-declarations \
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
        exit 1
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} app_data_sec_merge_config.c not found, skipping"
fi

# ============================================================================
# КОМПИЛЯЦИЯ AUTOCONFIG
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_autoconfig..."

if [ ! -f "app_data_sec_autoconfig.c" ]; then
    echo -e "${GREEN}[OK]${NC} Not found app_data_sec_autoconfig.c"
    exit 1
EOF
    echo -e "${BLUE}[INFO]${NC} Compiling autoconfig..."
    gcc -Wall -O2 -o app_data_sec_autoconfig app_data_sec_autoconfig.c 2>&1

    if [ ! -f "app_data_sec_autoconfig" ]; then
        echo -e "${RED}[ERROR]${NC} Autoconfig compilation failed!"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Autoconfig compiled"
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
if [ -f "app_data_sec_watchdog_informer.c" ]; then
    WATCHDOG_SRC="app_data_sec_watchdog_informer.c"
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
# КОМПИЛЯЦИЯ APP_DATA_SEC_MESSAGES_TO_SYSLOG (ВСЕГДА)
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Building app_data_sec_messages_to_syslog..."

# Поиск исходника messages_to_syslog
MESSAGES_SRC=""
if [ -f "app_data_sec_messages_to_syslog.c" ]; then
    MESSAGES_SRC="app_data_sec_messages_to_syslog.c"
elif [ -f "messages_monitor/app_data_sec_messages_to_syslog.c" ]; then
    MESSAGES_SRC="messages_monitor/app_data_sec_messages_to_syslog.c"
else
    MESSAGES_SRC=$(find . -name "app_data_sec_messages_to_syslog.c" -type f 2>/dev/null | head -1)
fi

INSTALL_MESSAGES=0
ENABLE_MESSAGES_SERVICE=0  # По умолчанию НЕ включаем сервис

if [ -n "$MESSAGES_SRC" ] && [ -f "$MESSAGES_SRC" ]; then
    echo -e "${BLUE}[INFO]${NC} Found: $MESSAGES_SRC"
    echo -e "${BLUE}[INFO]${NC} Compiling messages_to_syslog..."
    gcc -Wall -O2 -o app_data_sec_messages_to_syslog "$MESSAGES_SRC" 2>&1

    if [ -f "app_data_sec_messages_to_syslog" ]; then
        echo -e "${GREEN}[OK]${NC} messages_to_syslog compiled"
        INSTALL_MESSAGES=1

        echo ""
        echo -e "${YELLOW}[INFO]${NC} app_data_sec_messages_to_syslog is a monitoring tool"
        echo "that reads trace_pipe and forwards BPF logs to syslog."
        echo ""
        echo -e "${YELLOW}[INFO]${NC} The service will read from /sys/kernel/debug/tracing/trace_pipe"
        echo "and forward BPF messages to syslog with process chain information."
        echo ""
#         read -p "Enable app_data_sec_messages service to start automatically? (y/N) " -n 1 -r
#         echo
#         if [[ $REPLY =~ ^[Yy]$ ]]; then
#             ENABLE_MESSAGES_SERVICE=1
#             echo -e "${GREEN}[OK]${NC} Service will be enabled"
#         else
#             ENABLE_MESSAGES_SERVICE=0
#             echo -e "${YELLOW}[INFO]${NC} Service will be installed but NOT enabled"
#             echo "To enable later: sudo systemctl enable --now app_data_sec_messages"
#         fi
    else
        echo -e "${RED}[ERROR]${NC} messages_to_syslog compilation failed!"
        INSTALL_MESSAGES=0
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} app_data_sec_messages_to_syslog.c not found, skipping"
fi

# ============================================================================
# УСТАНОВКА ФАЙЛОВ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Installing files..."

# Создаём директории
mkdir -p "$INSTALL_PATH"
mkdir -p "$BPF_OBJ_PATH"
mkdir -p "$LOG_PATH"
mkdir -p "$CONFIGS_DIR"

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

# Устанавливаем autoconfig
if [ -f "app_data_sec_autoconfig" ]; then
    cp -f app_data_sec_autoconfig "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/app_data_sec_autoconfig"
    echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_autoconfig"

    ln -sf "$INSTALL_PATH/app_data_sec_autoconfig" /usr/bin/app_data_sec_autoconfig 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_autoconfig"
fi

# Устанавливаем messages_to_syslog (ВСЕГДА, если скомпилирован)
if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "app_data_sec_messages_to_syslog" ]; then
    cp -f app_data_sec_messages_to_syslog "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/app_data_sec_messages_to_syslog"
    echo -e "${GREEN}[OK]${NC} Installed: $INSTALL_PATH/app_data_sec_messages_to_syslog"
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

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    ln -sf "$INSTALL_PATH/app_data_sec_messages_to_syslog" /usr/bin/app_data_sec_messages_to_syslog 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Created symlink: /usr/bin/app_data_sec_messages_to_syslog"
fi


# ============================================================================
# ИМПОРТ КОНФИГУРАЦИЙ (АВТОМАТИЧЕСКИЙ)
# ============================================================================

# Создаём и настраиваем права для autoconfig директории
if [ -d "$AUTOCONFIG_DIR" ]; then
    chown root:root "$AUTOCONFIG_DIR"
    chmod 750 "$AUTOCONFIG_DIR"
    echo -e "${GREEN}[OK]${NC} Set permissions: $AUTOCONFIG_DIR (root:root, drwx------)"
else
    mkdir -p "$AUTOCONFIG_DIR"
    chown root:root "$AUTOCONFIG_DIR"
    chmod 750 "$AUTOCONFIG_DIR"
    echo -e "${GREEN}[OK]${NC} Created and set permissions: $AUTOCONFIG_DIR (root:root, drwxr-----)"
fi

# Проверяем наличие merge_config
if [ -f "$INSTALL_PATH/app_data_sec_merge_config" ]; then
    # Запускаем merge_config с autoconfig директорией (тихо, без лишних сообщений)
    "$INSTALL_PATH/app_data_sec_merge_config" -m "$CONFIG_PATH" "$AUTOCONFIG_DIR" --autoconfig -y 2>/dev/null || true
fi

# ============================================================================
# КОНФИГУРАЦИЯ (только при новой установке или если нет конфига)
# ============================================================================

if [ ! -f "$CONFIG_PATH" ]; then
    echo -e "\n${BLUE}[INFO]${NC} Creating default configuration..."
    cat > "$CONFIG_PATH" << 'EOF'
# /etc/app_data_sec.conf
# Конфигурация для eBPF блокировщика доступа к папкам
#
# ============================================================================
# enable - включение/отключение защиты
# ============================================================================
# enable = yes|no - включает или отключает все ограничения
#   Пример: enable = yes
#
# ============================================================================
# protect - защита папок
# ============================================================================
# protect <path> [allowed_prog1] [allowed_prog2] ... - защищает папку
#   path - путь к папке (можно использовать ~ для домашней директории пользователя)
#   allowed_prog - абсолютный путь к программе, которая может обходить защиту (опционально)
#   Пути с пробелами можно заключать в кавычки: "path with spaces"
#   Примеры:
#     protect /home/user/.test_app /bin/konsole /usr/bin/bash
#     protect ~/.secret_folder /bin/my_app
#     protect "/home/user/My Documents" "/usr/bin/my app"
#
# ============================================================================
# scan_mount - автоматическое сканирование при монтировании
# ============================================================================
# scan_mount <path> - отслеживает появление/монтирование указанного пути
#   При обнаружении пути выполняется полное сканирование шаблонов protect.
#   Это позволяет автоматически применять защиту к папкам, которые появляются
#   после монтирования внешних носителей, сетевых разделов и т.д.
#   ~ для домашней директории не доступна, можно использовать только абсолютные пути.
#   Пути с пробелами можно заключать в кавычки: "path with spaces"
#   Примеры:
#     scan_mount /mnt/external
#     scan_mount /media/usb
#     scan_mount ~/mnt/network
#     scan_mount "/mnt/My Drive"
#
#   Примечание: сканирование выполняется каждые 0,5 секунды, проверяя наличие
#   указанных путей. Как только путь появляется (монтируется), запускается
#   полное сканирование всех шаблонов protect.
# ============================================================================

enable = yes

# ============================================================================
# Примеры защищенных папок
# ============================================================================
# protect /home/user/.test_app /bin/konsole
# protect ~/.secret_folder

# ============================================================================
# Примеры отслеживаемых путей для автоматического сканирования
# ============================================================================
# scan_mount /mnt/external
# scan_mount /media/usb
EOF
    echo -e "${GREEN}[OK]${NC} Created: $CONFIG_PATH"
else
    echo -e "\n${YELLOW}[INFO]${NC} Config already exists, keeping existing"
    if [ "$IS_UPDATE" -eq 1 ]; then
        echo -e "${YELLOW}[INFO]${NC} To merge new entries, use: app_data_sec_merge_config <new.conf>"
    fi
fi

# ============================================================================
# ИМПОРТ КОНФИГУРАЦИЙ ПРИЛОЖЕНИЙ (НОВЫЙ БЛОК - ИСПРАВЛЕННЫЙ)
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking for application configurations..."

# Проверяем наличие папки с конфигами
if [ -d "$CONFIG_SOURCE_DIR" ] && [ "$(ls -A "$CONFIG_SOURCE_DIR" 2>/dev/null)" ]; then
    echo -e "${GREEN}[OK]${NC} Found configuration directory: $CONFIG_SOURCE_DIR"

    # Проверяем, есть ли .conf файлы
    conf_count=$(find "$CONFIG_SOURCE_DIR" -maxdepth 1 -name "*.conf" 2>/dev/null | wc -l)
    # Удаляем пробелы из результата
    conf_count=$(echo "$conf_count" | tr -d ' ')

    # Проверяем, что переменная не пустая и является числом
    if [ -n "$conf_count" ] && [ "$conf_count" -gt 0 ] 2>/dev/null; then
        echo -e "${BLUE}[INFO]${NC} Found $conf_count configuration files"

        # Предлагаем пользователю выбрать конфиги
        if select_app_configs; then
            # Импортируем выбранные конфиги
            import_selected_configs
        else
            echo -e "${YELLOW}[INFO]${NC} No configurations were selected or import was cancelled"
        fi
    else
        echo -e "${YELLOW}[INFO]${NC} No .conf files found in $CONFIG_SOURCE_DIR/"
    fi
else
    echo -e "${YELLOW}[INFO]${NC} No configuration directory found: $CONFIG_SOURCE_DIR"
    echo -e "${YELLOW}[INFO]${NC} To add application configurations, create this directory and add .conf files"
fi

# ============================================================================
# ЛОГ-ФАЙЛЫ
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Creating log files..."

for logfile in app_data_sec_loader.log app_data_sec_loader_error.log \
               app_data_sec_watchdog.log app_data_sec_autoconfig.log app_data_sec_watchdog_error.log \
               app_data_sec_messages.log app_data_sec_messages_error.log; do
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
Documentation=https://gitlab.com/v.kudashov.work/linux_app_data_sec/-/blob/main/README.md
# Убираем стандартные зависимости, чтобы сервис не ждал всё подряд
DefaultDependencies=no
# Запускаем как можно раньше (перед sysinit.target)
Before=sysinit.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/app_data_sec_loader -l 1
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=10

# Повышение приоритета
Nice=-20
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
IOSchedulingClass=realtime
IOSchedulingPriority=0

# Ускорение
TimeoutStartSec=10
TimeoutStopSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=app_data_sec_loader

# Доступ к системе
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
ReadWritePaths=/
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_SYS_NICE CAP_IPC_LOCK

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
Documentation=https://gitlab.com/v.kudashov.work/linux_app_data_sec/-/blob/main/README.md
# Убираем стандартные зависимости
DefaultDependencies=no
# Запускаем после загрузчика
After=app_data_sec_loader.service
Before=sysinit.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/app_data_sec_watchdog
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=2

# Повышение приоритета
Nice=-10
CPUSchedulingPolicy=rr
CPUSchedulingPriority=80
IOSchedulingClass=realtime
IOSchedulingPriority=0

# Ускорение
TimeoutStartSec=5
TimeoutStopSec=5

# Логи
StandardOutput=journal
StandardError=journal
SyslogIdentifier=app_data_sec_watchdog

# Снимаем все ограничения
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
PrivateDevices=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
#RestrictAddressFamilies=false
RestrictNamespaces=false
LockPersonality=false
MemoryDenyWriteExecute=false
RestrictRealtime=false
RestrictSUIDSGID=false

ReadWritePaths=/
ReadOnlyPaths=

CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID CAP_SYS_PTRACE CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_watchdog.service"

# ============================================================================
# СЕРВИС APP_DATA_SEC_AUTOCONFIG
# ============================================================================

cat > "$SERVICE_DIR/app_data_sec_autoconfig.service" << 'EOF'
[Unit]
Description=APP DATA SEC AutoConfig Service
Documentation=https://gitlab.com/v.kudashov.work/linux_app_data_sec/-/blob/main/README.md
After=app_data_sec_loader.service app_data_sec_watchdog.service
Wants=app_data_sec_loader.service

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/bin/app_data_sec_autoconfig
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=30

TimeoutStartSec=45
TimeoutStopSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=app_data_sec_autoconfig

# Мягкая изоляция, позволяющая запись в /etc
PrivateTmp=true
ProtectSystem=no
ProtectHome=true
NoNewPrivileges=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Явно разрешаем запись в /etc для конфигов
ReadWritePaths=/etc/app_data_sec.conf /etc/app_data_sec.autoconfig.timestamp /etc /run/app_data_sec_autoconfig.pid /run
ReadOnlyPaths=/usr/local/bin/app_data_sec_merge_config /usr/bin/app_data_sec_merge_config /run/app_data_sec_loader.pid

# Минимальные capabilities для работы с файлами в /etc
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_autoconfig.service"

# ============================================================================
# СЕРВИС APP_DATA_SEC_MESSAGES (опционально)
# ============================================================================

#if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
#    echo -e "\n${BLUE}[INFO]${NC} Creating systemd service for messages_to_syslog..."
#
#    cat > "$SERVICE_DIR/app_data_sec_messages.service" << 'EOF'
#[Unit]
#Description=APP DATA SEC Messages to Syslog Service
#Documentation=https://gitlab.com/v.kudashov.work/linux_app_data_sec/-/blob/main/README.md
#After=app_data_sec_loader.service
#Before=sysinit.target
#
#[Service]
#Type=simple
#User=root
#Group=root
## Используем полный путь
#ExecStart=/usr/local/bin/app_data_sec_messages_to_syslog
#ExecStop=/bin/kill -SIGTERM $MAINPID
#Restart=always
#RestartSec=5
#
## Логи
#StandardOutput=journal
#StandardError=journal
#SyslogIdentifier=app_data_sec_messages
#
## Снимаем все ограничения
#PrivateTmp=false
#ProtectSystem=false
#ProtectHome=false
#NoNewPrivileges=false
#PrivateDevices=false
#ProtectKernelTunables=false
#ProtectKernelModules=false
#ProtectControlGroups=false
#RestrictAddressFamilies=false
#RestrictNamespaces=false
#LockPersonality=false
#MemoryDenyWriteExecute=false
#RestrictRealtime=false
#RestrictSUIDSGID=false
#
## Разрешаем доступ к /proc и /sys
#ReadWritePaths=/
#ReadOnlyPaths=
#ReadWritePaths=/sys/kernel/debug/tracing
#ReadWritePaths=/proc
#
## Даем необходимые capabilities
#CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYSLOG CAP_DAC_OVERRIDE
#AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYSLOG CAP_DAC_OVERRIDE
#
#[Install]
#WantedBy=multi-user.target
#EOF
#
#    echo -e "${GREEN}[OK]${NC} Created: $SERVICE_DIR/app_data_sec_messages.service"
#
#    if [ "$ENABLE_MESSAGES_SERVICE" -eq 1 ]; then
#        systemctl enable app_data_sec_messages 2>/dev/null || true
#        echo -e "${GREEN}[OK]${NC} Service enabled: app_data_sec_messages"
#    else
#        echo -e "${YELLOW}[INFO]${NC} Service installed but NOT enabled"
#        echo "To enable: sudo systemctl enable --now app_data_sec_messages"
#    fi
#fi

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

# Запускаем messages (если включен)
#if [ "$INSTALL_MESSAGES" -eq 1 ] && [ "$ENABLE_MESSAGES_SERVICE" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
#    systemctl restart app_data_sec_messages
#fi

# Запускаем autoconfig
if [ -f "$INSTALL_PATH/app_data_sec_autoconfig" ]; then
    systemctl daemon-reload
    systemctl enable app_data_sec_autoconfig 2>/dev/null || true
    systemctl restart app_data_sec_autoconfig
    echo -e "${GREEN}[OK]${NC} Service started: app_data_sec_autoconfig"
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

echo ""
echo -e "${BLUE}app_data_sec_autoconfig:${NC}"
systemctl status app_data_sec_autoconfig --no-pager || true

#if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
#    echo ""
#    echo -e "${BLUE}app_data_sec_messages:${NC}"
#    if [ "$ENABLE_MESSAGES_SERVICE" -eq 1 ]; then
#        systemctl status app_data_sec_messages --no-pager || true
#    else
#        echo -e "  ${YELLOW}Service installed but not enabled${NC}"
#        echo "  To enable: sudo systemctl enable --now app_data_sec_messages"
#    fi
#fi

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

echo ""
echo -e "${BLUE}app_data_sec_autoconfig logs:${NC}"
journalctl -u app_data_sec_autoconfig -n 5 --no-pager 2>/dev/null || echo "  No logs yet"

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    echo ""
    echo -e "${BLUE}app_data_sec_messages logs:${NC}"
    journalctl -u app_data_sec_messages -n 5 --no-pager 2>/dev/null || echo "  No logs yet"
fi

# ============================================================================
# ПРОВЕРКА BPF
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Checking BPF programs..."

if command -v bpftool &> /dev/null; then
    BPF_PROGS=$(bpftool prog list 2>/dev/null | grep -c "block_" || echo "0")
    echo -e "  BPF programs loaded: $BPF_PROGS"

    # Проверяем карты
    echo -e "\n${BLUE}[INFO]${NC} BPF maps:"
    bpftool map list 2>/dev/null | grep -E "(folder_config|folder_allowed)" || echo "  No maps found"
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
  $INSTALL_PATH/app_data_sec_autoconfig
EOF

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    echo "  $INSTALL_PATH/app_data_sec_messages_to_syslog"
fi

cat << EOF
  $BPF_OBJ_PATH/app_data_sec.bpf.o
  $CONFIG_PATH
EOF

if [ -d "$CONFIGS_DIR" ] && [ "$(ls -A "$CONFIGS_DIR" 2>/dev/null)" ]; then
    echo "  $CONFIGS_DIR/ (application configurations)"
fi

cat << EOF

${BLUE}Services:${NC}
  app_data_sec_loader   - Main protection service
  app_data_sec_watchdog - Watchdog service (creates desktop file on errors)
  app_data_sec_autoconfig - AutoConfig service (monitors /etc/app_data_sec.autoconfig/)
EOF

#if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
#    if [ "$ENABLE_MESSAGES_SERVICE" -eq 1 ]; then
#        echo "  app_data_sec_messages - Monitoring service (active)"
#    else
#        echo "  app_data_sec_messages - Monitoring service (installed, disabled)"
#    fi
#fi

cat << EOF

${BLUE}Watchdog:${NC}
  When app_data_sec_loader stops, watchdog creates:
  app_data_sec_errors.txt on each user's desktop

EOF

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    echo -e "${BLUE}Messages to Syslog:${NC}"
    echo "  Reads trace_pipe and forwards BPF logs to syslog"
    echo "  Shows process chain for each blocked access"
    echo ""
fi

cat << EOF
${BLUE}Commands:${NC}
  sudo systemctl status app_data_sec_loader
  sudo systemctl status app_data_sec_watchdog
  sudo systemctl status app_data_sec_autoconfig
  sudo journalctl -u app_data_sec_loader -f
  sudo journalctl -u app_data_sec_watchdog -f
  sudo journalctl -u app_data_sec_autoconfig -f
EOF

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    echo "  sudo systemctl status app_data_sec_messages"
    echo "  sudo journalctl -u app_data_sec_messages -f"
fi

cat << EOF

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

if [ "$INSTALL_MESSAGES" -eq 1 ] && [ -f "$INSTALL_PATH/app_data_sec_messages_to_syslog" ]; then
    echo ""
    echo -e "${BLUE}Messages Monitor:${NC}"
    echo "  To see BPF logs in syslog:"
    echo "  sudo journalctl -u app_data_sec_messages -f"
    echo "  Or: tail -f /var/log/syslog | grep APP_DATA_SEC"
    echo ""
    echo "  To stop messages service:"
    echo "  sudo systemctl stop app_data_sec_messages"
    echo "  sudo systemctl disable app_data_sec_messages"
fi

if [ "$IS_UPDATE" -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}[INFO]${NC} If you experience issues after update:"
    echo "  1. Check logs: sudo journalctl -u app_data_sec_loader -f"
    echo "  2. Restart: sudo systemctl restart app_data_sec_loader"
    echo "  3. Restore backup: sudo cp $BACKUP_DIR/app_data_sec_loader.backup $INSTALL_PATH/"
fi

echo -e "\n${GREEN}Done!${NC}"
