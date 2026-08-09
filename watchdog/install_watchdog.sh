#!/bin/bash
# install_watchdog.sh - Полная установка watchdog сервиса

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Конфигурация
WATCHDOG_SRC="app_data_sec_watchdog_zenity.c"
WATCHDOG_BIN="app_data_sec_watchdog"
INSTALL_PATH="/usr/local/bin"
SERVICE_NAME="app_data_sec_watchdog"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/app_data_sec_watchdog.log"
ERROR_LOG="/var/log/app_data_sec_watchdog_error.log"

# ============================================================================
# ФУНКЦИИ
# ============================================================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}   APP DATA SEC - WATCHDOG INSTALL${NC}"
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

    # Проверка Zenity
    if ! command -v zenity &> /dev/null; then
        print_warning "Zenity not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y zenity 2>/dev/null || true
    fi

    # Проверка pkg-config
    if ! command -v pkg-config &> /dev/null; then
        print_warning "pkg-config not found. Installing..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y pkg-config 2>/dev/null || true
    fi

    print_success "Dependencies OK"
}

compile_watchdog() {
    print_info "Compiling watchdog..."

    # Проверяем наличие исходного файла
    if [ ! -f "$WATCHDOG_SRC" ]; then
        print_error "Source file $WATCHDOG_SRC not found!"
        print_info "Looking for alternative source files..."

        # Ищем другие варианты
        if [ -f "app_data_sec_watchdog.c" ]; then
            WATCHDOG_SRC="app_data_sec_watchdog.c"
            print_info "Found: $WATCHDOG_SRC"
        elif [ -f "watchdog.c" ]; then
            WATCHDOG_SRC="watchdog.c"
            print_info "Found: $WATCHDOG_SRC"
        else
            print_error "No source file found!"
            exit 1
        fi
    fi

    # Компилируем
    print_info "Compiling $WATCHDOG_SRC..."
    gcc -Wall -O2 -o "$WATCHDOG_BIN" "$WATCHDOG_SRC" $(pkg-config --cflags --libs gtk+-3.0 2>/dev/null) -lm 2>&1

    if [ $? -ne 0 ]; then
        # Если GTK не найден, пробуем без него (с Zenity)
        print_warning "GTK not found, compiling with Zenity support only..."
        gcc -Wall -O2 -o "$WATCHDOG_BIN" "$WATCHDOG_SRC" -lm 2>&1
    fi

    if [ ! -f "$WATCHDOG_BIN" ]; then
        print_error "Compilation failed!"
        exit 1
    fi

    print_success "Compiled: $WATCHDOG_BIN"
}

install_binary() {
    print_info "Installing binary to $INSTALL_PATH..."

    mkdir -p "$INSTALL_PATH"
    cp "$WATCHDOG_BIN" "$INSTALL_PATH/"
    chmod 755 "$INSTALL_PATH/$WATCHDOG_BIN"

    if [ -f "$INSTALL_PATH/$WATCHDOG_BIN" ]; then
        print_success "Installed: $INSTALL_PATH/$WATCHDOG_BIN"
    else
        print_error "Failed to install binary!"
        exit 1
    fi
}

create_log_files() {
    print_info "Creating log files..."

    touch "$LOG_FILE" 2>/dev/null || true
    touch "$ERROR_LOG" 2>/dev/null || true
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    chmod 644 "$ERROR_LOG" 2>/dev/null || true

    print_success "Log files created"
}

detect_display() {
    # Определяем DISPLAY
    DISPLAY_VAR=":0"

    # Проверяем через who
    if command -v who &> /dev/null; then
        DISPLAY_VAR=$(who 2>/dev/null | grep -E "\(:[0-9]+\)" | head -1 | sed -E 's/.*\((:[0-9]+)\)$/\1/' || echo ":0")
    fi

    # Проверяем через ps
    if [ "$DISPLAY_VAR" = ":0" ] || [ -z "$DISPLAY_VAR" ]; then
        DISPLAY_VAR=$(ps aux 2>/dev/null | grep -E "[X]org|[X]11" | head -1 | grep -oE ":[0-9]+" | head -1 || echo ":0")
    fi

    # Проверяем через env
    if [ -z "$DISPLAY_VAR" ] || [ "$DISPLAY_VAR" = ":0" ]; then
        DISPLAY_VAR=${DISPLAY:-":0"}
    fi

    echo "$DISPLAY_VAR"
}

create_service() {
    print_info "Creating systemd service..."

    DISPLAY_VAR=$(detect_display)
    print_info "Using DISPLAY: $DISPLAY_VAR"

    # Создаём сервисный файл
    cat > "$SERVICE_FILE" << 'SERVICE_EOF'
[Unit]
Description=APP DATA SEC Watchdog Service
Documentation=https://github.com/your-repo/app_data_sec
After=network.target multi-user.target graphical.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
Environment=DISPLAY=:0
Environment=XAUTHORITY=/root/.Xauthority
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus
ExecStart=/usr/local/bin/app_data_sec_watchdog -z
ExecStop=/bin/kill -SIGTERM $MAINPID
ExecReload=/bin/kill -SIGHUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=append:/var/log/app_data_sec_watchdog.log
StandardError=append:/var/log/app_data_sec_watchdog_error.log
SyslogIdentifier=app_data_sec_watchdog
PIDFile=/run/app_data_sec_watchdog.pid

# Security (сняты ограничения для GUI)
PrivateTmp=false
ProtectSystem=false
ProtectHome=false
NoNewPrivileges=false
ReadWritePaths=/ /var/log /tmp /run/user/0 /home
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID

[Install]
WantedBy=multi-user.target graphical.target
SERVICE_EOF

    # Заменяем DISPLAY на определённый
    sed -i "s/Environment=DISPLAY=:0/Environment=DISPLAY=${DISPLAY_VAR}/g" "$SERVICE_FILE"

    print_success "Service file created: $SERVICE_FILE"
}

setup_xauthority() {
    print_info "Setting up Xauthority..."

    # Создаём директорию для Xauthority
    mkdir -p /run/user/0
    chmod 700 /run/user/0

    # Ищем Xauthority файл
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
        print_success "Xauthority set up from: $XAUTH_FILE"
    else
        print_warning "No Xauthority file found. GUI dialogs may not work."
        print_info "To fix, run: xauth generate :0 . trusted"
    fi
}

enable_service() {
    print_info "Enabling and starting service..."

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl restart "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Service is running"
    else
        print_warning "Service failed to start. Checking logs..."
        journalctl -u "$SERVICE_NAME" -n 10 --no-pager || true
    fi
}

check_status() {
    echo ""
    print_info "Service status:"
    systemctl status "$SERVICE_NAME" --no-pager || true

    echo ""
    print_info "Last log entries:"
    tail -n 10 "$LOG_FILE" 2>/dev/null || echo "No log entries yet"
}

show_usage() {
    cat << EOF

${GREEN}✅ Watchdog installed successfully!${NC}

${BLUE}Commands:${NC}
  sudo systemctl start $SERVICE_NAME     - Start watchdog
  sudo systemctl stop $SERVICE_NAME      - Stop watchdog
  sudo systemctl restart $SERVICE_NAME   - Restart watchdog
  sudo systemctl status $SERVICE_NAME    - Check status
  sudo systemctl enable $SERVICE_NAME    - Enable on boot
  sudo systemctl disable $SERVICE_NAME   - Disable on boot

${BLUE}Logs:${NC}
  sudo journalctl -u $SERVICE_NAME -f    - Real-time logs
  sudo tail -f $LOG_FILE                 - Standard log
  sudo tail -f $ERROR_LOG                - Error log

${BLUE}Files:${NC}
  Binary: $INSTALL_PATH/$WATCHDOG_BIN
  Service: $SERVICE_FILE
  Log: $LOG_FILE

${BLUE}Uninstall:${NC}
  sudo systemctl stop $SERVICE_NAME
  sudo systemctl disable $SERVICE_NAME
  sudo rm -f $SERVICE_FILE
  sudo rm -f $INSTALL_PATH/$WATCHDOG_BIN
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
    compile_watchdog
    install_binary
    create_log_files
    setup_xauthority
    create_service
    enable_service
    check_status
    show_usage

    echo -e "\n${GREEN}Installation completed successfully!${NC}"
}

# ============================================================================
# ЗАПУСК
# ============================================================================

main "$@"
