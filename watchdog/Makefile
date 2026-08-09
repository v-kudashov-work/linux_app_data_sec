# Makefile.watchdog
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = `pkg-config --cflags --libs gtk+-3.0` -lm

TARGET = app_data_sec_watchdog
SRC = app_data_sec_watchdog.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod 755 /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)

run: $(TARGET)
	sudo ./$(TARGET) -d

.PHONY: all clean install uninstall run
