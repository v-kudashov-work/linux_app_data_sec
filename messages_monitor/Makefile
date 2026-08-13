# Makefile для app_data_sec_messages_to_syslog

# Настройки
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS =

# Имя программы
TARGET = app_data_sec_messages_to_syslog
SRC = $(TARGET).c

# Цели по умолчанию
all: $(TARGET)

# Сборка программы
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Установка в систему
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin/"
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod 755 /usr/local/bin/$(TARGET)

# Удаление из системы
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin/"
	sudo rm -f /usr/local/bin/$(TARGET)

# Очистка
clean:
	rm -f $(TARGET)
	rm -f *.o

# Полная очистка
distclean: clean
	rm -f *~

# Запуск в фоновом режиме как демон
run-daemon: $(TARGET)
	@echo "Starting $(TARGET) as daemon..."
	sudo nohup ./$(TARGET) > /dev/null 2>&1 &
	@echo "Started with PID: $$(pgrep $(TARGET) | head -1)"

# Запуск для отладки (с выводом на консоль)
run: $(TARGET)
	sudo ./$(TARGET)

# Остановка демона
stop:
	@echo "Stopping $(TARGET)..."
	sudo pkill -f $(TARGET) || true
	@echo "Stopped"

# Перезапуск демона
restart: stop run-daemon

# Установка как systemd сервис (опционально)
install-service:
	@echo "Installing systemd service..."
	@echo "[Unit]" > /tmp/$(TARGET).service
	@echo "Description=App Data Sec Messages to Syslog" >> /tmp/$(TARGET).service
	@echo "After=network.target" >> /tmp/$(TARGET).service
	@echo "" >> /tmp/$(TARGET).service
	@echo "[Service]" >> /tmp/$(TARGET).service
	@echo "Type=simple" >> /tmp/$(TARGET).service
	@echo "ExecStart=/usr/local/bin/$(TARGET)" >> /tmp/$(TARGET).service
	@echo "Restart=always" >> /tmp/$(TARGET).service
	@echo "RestartSec=10" >> /tmp/$(TARGET).service
	@echo "" >> /tmp/$(TARGET).service
	@echo "[Install]" >> /tmp/$(TARGET).service
	@echo "WantedBy=multi-user.target" >> /tmp/$(TARGET).service
	sudo mv /tmp/$(TARGET).service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Service installed. Use:"
	@echo "  sudo systemctl start $(TARGET)"
	@echo "  sudo systemctl enable $(TARGET)"
	@echo "  sudo systemctl status $(TARGET)"

# Удаление systemd сервиса
uninstall-service:
	@echo "Removing systemd service..."
	sudo systemctl stop $(TARGET) || true
	sudo systemctl disable $(TARGET) || true
	sudo rm -f /etc/systemd/system/$(TARGET).service
	sudo systemctl daemon-reload
	@echo "Service removed"

# Проверка синтаксиса
check:
	$(CC) $(CFLAGS) -fsyntax-only $(SRC)

# Получить помощь
help:
	@echo "Available targets:"
	@echo "  all           - Build the program (default)"
	@echo "  clean         - Remove built files"
	@echo "  distclean     - Remove all generated files"
	@echo "  install       - Install to /usr/local/bin/"
	@echo "  uninstall     - Remove from /usr/local/bin/"
	@echo "  run           - Run with sudo"
	@echo "  run-daemon    - Run in background as daemon"
	@echo "  stop          - Stop the daemon"
	@echo "  restart       - Restart the daemon"
	@echo "  install-service - Install as systemd service"
	@echo "  uninstall-service - Remove systemd service"
	@echo "  check         - Check syntax only"
	@echo "  help          - Show this help"

.PHONY: all clean distclean install uninstall run run-daemon stop restart \
        install-service uninstall-service check help
