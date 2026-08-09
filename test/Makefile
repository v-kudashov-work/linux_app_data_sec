# Makefile.test
CC = gcc
CFLAGS = -Wall -O2 -I.
LDFLAGS = -lbpf -lelf -lz

TARGET = test_app_data_sec

all: $(TARGET)

$(TARGET): test_app_data_sec.c
	$(CC) $(CFLAGS) -o $(TARGET) test_app_data_sec.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all clean run
