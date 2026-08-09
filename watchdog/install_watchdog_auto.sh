#!/bin/bash
# build_and_install_watchdog.sh - Скрипт сборки и установки app_data_sec_watchdog

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
WATCHDOG_BIN="app_data_sec_watchdog"
WATCHDOG_INSTALL_PATH="/usr/local/bin/$WATCHDOG_BIN"
WATCHDOG_SRC="app_data_sec_watchdog.c"
WATCHDOG_SERVICE="/etc/systemd/system/app_data_sec_watchdog.service"
WATCHDOG_LOG="/var/log/app_data_sec_watchdog.log"
WATCHDOG_ERROR_LOG="/var/log/app_data_sec_watchdog_error.log"

# ============================================================================
# ФУНКЦИИ
# ============================================================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}   APP DATA SEC - BUILD & INSTALL${NC}"
    echo -e "${BLUE}         WATCHDOG SERVICE${NC}"
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
        apt-get update -qq
        apt-get install -y build-essential
    fi

    # Проверка GTK
    if ! pkg-config --exists gtk+-3.0 2>/dev/null; then
        print_warning "GTK3 development libraries not found. Installing..."
        apt-get update -qq
        apt-get install -y libgtk-3-dev pkg-config
    fi

    # Проверка systemd
    if ! command -v systemctl &> /dev/null; then
        print_error "systemd not found. This script requires systemd."
        exit 1
    fi

    print_success "All dependencies satisfied"
}

build_watchdog() {
    print_info "Building watchdog binary..."

    # Проверяем наличие исходного файла
    if [ ! -f "$WATCHDOG_SRC" ]; then
        print_error "Source file $WATCHDOG_SRC not found!"
        print_info "Please make sure you are in the directory with the source code."
        exit 1
    fi

    # Компилируем
    gcc -Wall -O2 -o "$WATCHDOG_BIN" "$WATCHDOG_SRC" $(pkg-config --cflags --libs gtk+-3.0) -lm 2>&1

    if [ $? -ne 0 ]; then
        print_error "Compilation failed!"
        exit 1
    fi

    if [ ! -f "$WATCHDOG_BIN" ]; then
        print_error "Binary not created after compilation!"
        exit 1
    fi

    print_success "Watchdog binary built: $WATCHDOG_BIN"
}

install_watchdog() {
    print_info "Installing watchdog binary to $WATCHDOG_INSTALL_PATH..."

    # Копируем бинарник
    cp "$WATCHDOG_BIN" "$WATCHDOG_INSTALL_PATH"
    chmod 755 "$WATCHDOG_INSTALL_PATH"

    print_success "Watchdog installed to $WATCHDOG_INSTALL_PATH"
}

create_log_files() {
    print_info "Creating log files..."

    touch "$WATCHDOG_LOG" 2>/dev/null || true
    touch "$WATCHDOG_ERROR_LOG" 2>/dev/null || true
    chmod 644 "$WATCHDOG_LOG" 2>/dev/null || true
    chmod 644 "$WATCHDOG_ERROR_LOG" 2>/dev/null || true

    print_success "Log files created"
}

create_service_file() {
    print_info "Creating systemd service file..."

    # Проверяем путь к app_data_sec_loader
    APP_DATA_SEC_PATH=$(which app_data_sec_loader 2>/dev/null || echo "/usr/local/bin/app_data_sec_loader")

    cat > "$WATCHDOG_SERVICE" << EOF
[Unit]
Description=APP DATA SEC Watchdog Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/bin/bash -c 'sleep 5'
ExecStart=$WATCHDOG_INSTALL_PATH -d
ExecStop=/bin/kill -SIGTERM \$MAINPID
ExecReload=/bin/kill -SIGHUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:$WATCHDOG_LOG
StandardError=append:$WATCHDOG_ERROR_LOG
SyslogIdentifier=app_data_sec_watchdog
PIDFile=/run/app_data_sec_watchdog.pid

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

    print_success "Service file created at $WATCHDOG_SERVICE"
}

reload_systemd() {
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    print_success "Systemd reloaded"
}

enable_service() {
    print_info "Enabling service..."
    systemctl enable app_data_sec_watchdog.service
    print_success "Service enabled"
}

start_service() {
    print_info "Starting service..."
    systemctl start app_data_sec_watchdog.service
    print_success "Service started"
}

check_status() {
    print_info "Checking service status..."
    systemctl status app_data_sec_watchdog.service --no-pager || true
}

show_usage() {
    cat << EOF

${GREEN}Installation complete!${NC}

${BLUE}Service commands:${NC}
  sudo systemctl start app_data_sec_watchdog     - Start watchdog
  sudo systemctl stop app_data_sec_watchdog      - Stop watchdog
  sudo systemctl restart app_data_sec_watchdog   - Restart watchdog
  sudo systemctl status app_data_sec_watchdog    - Check status
  sudo systemctl enable app_data_sec_watchdog    - Enable on boot
  sudo systemctl disable app_data_sec_watchdog   - Disable on boot

${BLUE}Log files:${NC}
  $WATCHDOG_LOG          - Main log
  $WATCHDOG_ERROR_LOG    - Error log

${BLUE}Watchdog binary:${NC}
  $WATCHDOG_INSTALL_PATH

${BLUE}Configuration:${NC}
  Check interval: 600 seconds (10 minutes)
  Restart delay: 5 seconds
  Max restarts: 3 attempts

${BLUE}To view logs in real-time:${NC}
  sudo journalctl -u app_data_sec_watchdog -f
  sudo tail -f $WATCHDOG_LOG

${BLUE}To uninstall:${NC}
  sudo systemctl stop app_data_sec_watchdog
  sudo systemctl disable app_data_sec_watchdog
  sudo rm -f $WATCHDOG_SERVICE
  sudo rm -f $WATCHDOG_INSTALL_PATH
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
    build_watchdog
    install_watchdog
    create_log_files
    create_service_file
    reload_systemd

    # Спрашиваем пользователя
    echo ""
    read -p "Enable and start watchdog service? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        enable_service
        start_service
        check_status
    else
        print_info "Service created but not started."
        print_info "To start manually: sudo systemctl start app_data_sec_watchdog"
    fi

    show_usage

    echo -e "\n${GREEN}Installation completed successfully!${NC}"
}

# ============================================================================
# ЗАПУСК
# ============================================================================

main "$@"
