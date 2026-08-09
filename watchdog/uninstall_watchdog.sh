#!/bin/bash
# uninstall_watchdog.sh - Полное удаление watchdog сервиса

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Конфигурация
WATCHDOG_BIN="app_data_sec_watchdog"
INSTALL_PATH="/usr/local/bin"
SERVICE_NAME="app_data_sec_watchdog"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/app_data_sec_watchdog.log"
ERROR_LOG="/var/log/app_data_sec_watchdog_error.log"
PID_FILE="/run/app_data_sec_watchdog.pid"

# ============================================================================
# ФУНКЦИИ
# ============================================================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}   APP DATA SEC - UNINSTALL WATCHDOG${NC}"
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

stop_service() {
    print_info "Stopping service..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        print_success "Service stopped"
    else
        print_warning "Service is not running"
    fi
}

disable_service() {
    print_info "Disabling service..."

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        print_success "Service disabled"
    else
        print_warning "Service is not enabled"
    fi
}

kill_processes() {
    print_info "Killing watchdog processes..."

    # Убиваем все процессы watchdog
    PIDS=$(pgrep -f "$WATCHDOG_BIN" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        for PID in $PIDS; do
            kill -9 "$PID" 2>/dev/null || true
        done
        print_success "Processes killed"
    else
        print_warning "No watchdog processes found"
    fi
}

remove_service_file() {
    print_info "Removing service file..."

    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        print_success "Service file removed"
    else
        print_warning "Service file not found"
    fi
}

remove_binary() {
    print_info "Removing binary..."

    if [ -f "${INSTALL_PATH}/${WATCHDOG_BIN}" ]; then
        rm -f "${INSTALL_PATH}/${WATCHDOG_BIN}"
        print_success "Binary removed"
    else
        print_warning "Binary not found at ${INSTALL_PATH}/${WATCHDOG_BIN}"
    fi

    # Проверяем другие возможные места
    OTHER_PATHS=(
        "/usr/bin/${WATCHDOG_BIN}"
        "/opt/${WATCHDOG_BIN}"
        "./${WATCHDOG_BIN}"
    )

    for path in "${OTHER_PATHS[@]}"; do
        if [ -f "$path" ]; then
            rm -f "$path"
            print_success "Removed: $path"
        fi
    done
}

remove_log_files() {
    print_info "Removing log files..."

    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
        print_success "Log file removed"
    else
        print_warning "Log file not found"
    fi

    if [ -f "$ERROR_LOG" ]; then
        rm -f "$ERROR_LOG"
        print_success "Error log removed"
    else
        print_warning "Error log not found"
    fi
}

remove_pid_file() {
    print_info "Removing PID file..."

    if [ -f "$PID_FILE" ]; then
        rm -f "$PID_FILE"
        print_success "PID file removed"
    else
        print_warning "PID file not found"
    fi
}

reload_systemd() {
    print_info "Reloading systemd..."
    systemctl daemon-reload
    print_success "Systemd reloaded"
}

confirm_remove_logs() {
    echo ""
    read -p "Remove log files? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        remove_log_files
    else
        print_info "Keeping log files: $LOG_FILE $ERROR_LOG"
    fi
}

confirm_remove_all() {
    echo ""
    print_warning "This will remove the watchdog service, binary, and optionally logs."
    read -p "Are you sure you want to continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Uninstall cancelled"
        exit 0
    fi
}

show_completion() {
    cat << EOF

${GREEN}✅ Watchdog uninstalled successfully!${NC}

${BLUE}Removed:${NC}
  - Service file: $SERVICE_FILE
  - Binary: ${INSTALL_PATH}/${WATCHDOG_BIN}
  - PID file: $PID_FILE

${BLUE}To verify:${NC}
  sudo systemctl status $SERVICE_NAME 2>/dev/null || echo "Service not found"
  ps aux | grep -v grep | grep $WATCHDOG_BIN || echo "No processes running"

EOF
}

# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

main() {
    print_header

    check_root
    confirm_remove_all

    stop_service
    disable_service
    kill_processes
    remove_service_file
    remove_binary
    remove_pid_file
    reload_systemd

    confirm_remove_logs

    show_completion
}

# ============================================================================
# ЗАПУСК
# ============================================================================

main "$@"
