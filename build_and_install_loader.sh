#!/bin/bash
# build_and_install_loader.sh - Сборка и установка app_data_sec_loader

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Конфигурация
LOADER_SRC="app_data_sec.bpf.c"
LOADER_BIN="app_data_sec_loader"
LOADER_C="app_data_sec_loader.c"
INSTALL_PATH="/usr/local/bin"
CONFIG_PATH="/etc/app_data_sec.conf"
CONFIG_BACKUP="/etc/app_data_sec.conf.bak"
BPFTOOL="bpftool"

# ============================================================================
# ФУНКЦИИ
# ============================================================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}   APP DATA SEC - BUILD & INSTALL${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    print_info "Checking dependencies..."

    # Проверка GCC
    if ! command -v gcc &> /dev/null; then
        print_warning "GCC not found. Installing build-essential..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y build-essential 2>/dev/null || true
    fi

    # Проверка Clang
    if ! command -v clang &> /dev/null; then
        print_warning "Clang not found. Installing clang..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y clang 2>/dev/null || true
    fi

    # Проверка bpftool
    if ! command -v $BPFTOOL &> /dev/null; then
        print_warning "bpftool not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y linux-tools-common linux-tools-$(uname -r) 2>/dev/null || true

        if ! command -v $BPFTOOL &> /dev/null; then
            print_warning "bpftool still not found. Installing from source..."
            if [ -d "/tmp/bpftool" ]; then
                rm -rf /tmp/bpftool
            fi
            git clone https://github.com/libbpf/bpftool.git /tmp/bpftool 2>/dev/null || true
            if [ -d "/tmp/bpftool" ]; then
                cd /tmp/bpftool
                make 2>/dev/null || true
                make install 2>/dev/null || true
                cd -
                rm -rf /tmp/bpftool
            fi
        fi
    fi

    # Проверка libbpf
    if ! pkg-config --exists libbpf 2>/dev/null; then
        print_warning "libbpf not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y libbpf-dev 2>/dev/null || true
    fi

    # Проверка libelf
    if ! pkg-config --exists libelf 2>/dev/null; then
        print_warning "libelf not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y libelf-dev 2>/dev/null || true
    fi

    # Проверка zlib
    if ! pkg-config --exists zlib 2>/dev/null; then
        print_warning "zlib not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y zlib1g-dev 2>/dev/null || true
    fi

    print_success "Dependencies OK"
}

check_kernel_support() {
    print_info "Checking kernel support..."

    # Проверка BTF
    if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
        print_warning "BTF not found. Kernel may not support CO-RE"
    else
        print_success "BTF found"
    fi

    # Проверка LSM
    if [ -f "/sys/kernel/security/lsm" ]; then
        LSM=$(cat /sys/kernel/security/lsm)
        if echo "$LSM" | grep -q "bpf"; then
            print_success "BPF LSM enabled: $LSM"
        else
            print_warning "BPF LSM not found in: $LSM"
            print_info "To enable, add 'bpf' to lsm= in /etc/default/grub"
        fi
    else
        print_warning "LSM not available"
    fi
}

generate_vmlinux_h() {
    print_info "Generating vmlinux.h..."

    if [ ! -f "vmlinux.h" ]; then
        if command -v $BPFTOOL &> /dev/null; then
            $BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || {
                print_warning "Failed to generate vmlinux.h, will try to use existing"
            }
        fi
    fi

    if [ -f "vmlinux.h" ]; then
        print_success "vmlinux.h generated"
    else
        print_warning "vmlinux.h not found, some BPF features may not work"
    fi
}

compile_bpf() {
    print_info "Compiling BPF program..."

    if [ ! -f "$LOADER_SRC" ]; then
        print_error "Source file $LOADER_SRC not found!"
        exit 1
    fi

    # Компилируем BPF программу
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c "$LOADER_SRC" -o "${LOADER_SRC%.c}.bpf.o" 2>&1 || {
        print_error "BPF compilation failed!"
        exit 1
    }

    if [ -f "${LOADER_SRC%.c}.bpf.o" ]; then
        print_success "BPF program compiled: ${LOADER_SRC%.c}.bpf.o"
    else
        print_error "BPF compilation failed!"
        exit 1
    fi
}

generate_skeleton() {
    print_info "Generating BPF skeleton..."

    if command -v $BPFTOOL &> /dev/null; then
        $BPFTOOL gen skeleton "${LOADER_SRC%.c}.bpf.o" > "${LOADER_SRC%.c}.skel.h" 2>/dev/null || {
            print_warning "Failed to generate skeleton, trying without sudo..."
            sudo $BPFTOOL gen skeleton "${LOADER_SRC%.c}.bpf.o" > "${LOADER_SRC%.c}.skel.h" 2>/dev/null || {
                print_warning "Could not generate skeleton, will try to compile anyway"
            }
        }
    fi

    if [ -f "${LOADER_SRC%.c}.skel.h" ]; then
        print_success "Skeleton generated: ${LOADER_SRC%.c}.skel.h"
    else
        print_warning "Skeleton not generated, compilation may fail"
    fi
}

compile_loader() {
    print_info "Compiling loader..."

    if [ ! -f "$LOADER_C" ]; then
        print_error "Loader source $LOADER_C not found!"
        exit 1
    fi

    # Компилируем загрузчик
    gcc -Wall -O2 -o "$LOADER_BIN" "$LOADER_C" -lbpf -lelf -lz 2>&1 || {
        print_error "Loader compilation failed!"
        exit 1
    }

    if [ -f "$LOADER_BIN" ]; then
        print_success "Loader compiled: $LOADER_BIN"
    else
        print_error "Loader compilation failed!"
        exit 1
    fi
}

install_binary() {
    print_info "Installing loader to $INSTALL_PATH..."

    mkdir -p "$INSTALL_PATH"
    cp "$LOADER_BIN" "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/$LOADER_BIN"

    if [ -f "$INSTALL_PATH/$LOADER_BIN" ]; then
        print_success "Installed: $INSTALL_PATH/$LOADER_BIN"
    else
        print_error "Failed to install binary!"
        exit 1
    fi
}

install_bpf_object() {
    print_info "Installing BPF object..."

    BPF_OBJ="${LOADER_SRC%.c}.bpf.o"
    if [ -f "$BPF_OBJ" ]; then
        mkdir -p /usr/local/lib/app_data_sec
        cp "$BPF_OBJ" /usr/local/lib/app_data_sec/
        print_success "BPF object installed: /usr/local/lib/app_data_sec/$BPF_OBJ"
    else
        print_warning "BPF object not found"
    fi
}

create_config() {
    print_info "Creating default configuration..."

    if [ -f "$CONFIG_PATH" ]; then
        print_warning "Configuration file already exists, backing up..."
        cp "$CONFIG_PATH" "$CONFIG_BACKUP"
    fi

    cat > "$CONFIG_PATH" << 'EOF'
# /etc/app_data_sec.conf
# Конфигурация для eBPF блокировщика доступа к папкам
#
# enable = yes|no - включает или отключает все ограничения
# protect <path> [allowed_prog1] [allowed_prog2] ... - защищает папку
#   path - путь к папке (можно использовать ~ для домашней директории)
#   allowed_prog - абсолютный путь к программе, которая может обходить защиту (опционально)
#
# Примеры:
# enable = yes
# protect /home/user/.test_app /bin/konsole /usr/bin/bash
# protect ~/.secret_folder /bin/my_app

enable = yes

# Защищаем папку /home/user/.test_app
# Разрешаем доступ для /bin/konsole и /usr/bin/bash
# protect /home/user/.test_app /bin/konsole /usr/bin/bash

# Защищаем папку .secret_folder в домашней директории КАЖДОГО пользователя
# protect ~/.secret_folder /bin/my_app

# Просто защищаем папку без белого списка
# protect /var/www/private
EOF

    chmod 644 "$CONFIG_PATH"
    print_success "Configuration created: $CONFIG_PATH"
}

create_service() {
    print_info "Creating systemd service..."

    SERVICE_FILE="/etc/systemd/system/app_data_sec_loader.service"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=APP DATA SEC Loader Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_PATH/$LOADER_BIN
ExecStop=/bin/kill -SIGTERM \$MAINPID
ExecReload=/bin/kill -SIGHUP \$MAINPID
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

    systemctl daemon-reload 2>/dev/null || true
    print_success "Service created: $SERVICE_FILE"
}

show_usage() {
    cat << EOF

${GREEN}✅ APP DATA SEC LOADER installed successfully!${NC}

${BLUE}Files:${NC}
  Binary: $INSTALL_PATH/$LOADER_BIN
  Config: $CONFIG_PATH
  BPF object: /usr/local/lib/app_data_sec/${LOADER_SRC%.c}.bpf.o
  Service: /etc/systemd/system/app_data_sec_loader.service

${BLUE}Commands:${NC}
  sudo $LOADER_BIN [log_level]     - Run loader (0=off, 1=blocked only, 2=everything)
  sudo systemctl start app_data_sec_loader     - Start service
  sudo systemctl stop app_data_sec_loader      - Stop service
  sudo systemctl status app_data_sec_loader    - Check status
  sudo systemctl enable app_data_sec_loader    - Enable on boot

${BLUE}Configuration:${NC}
  Edit config: sudo nano $CONFIG_PATH
  Reload config: sudo systemctl restart app_data_sec_loader

${BLUE}Logs:${NC}
  sudo journalctl -u app_data_sec_loader -f
  sudo tail -f /var/log/app_data_sec_loader.log

${BLUE}To uninstall:${NC}
  sudo systemctl stop app_data_sec_loader
  sudo systemctl disable app_data_sec_loader
  sudo rm -f $SERVICE_FILE
  sudo rm -f $INSTALL_PATH/$LOADER_BIN
  sudo rm -f /usr/local/lib/app_data_sec/${LOADER_SRC%.c}.bpf.o
  sudo systemctl daemon-reload

EOF
}

# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

main() {
    print_header

    check_root
    check_dependencies
    check_kernel_support
    generate_vmlinux_h
    compile_bpf
    generate_skeleton
    compile_loader
    install_binary
    install_bpf_object
    create_config
    create_service

    show_usage

    echo -e "\n${GREEN}Installation completed successfully!${NC}"
}

# ============================================================================
# ЗАПУСК
# ============================================================================

main "$@"
