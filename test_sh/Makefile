# Makefile для run_script

CC = gcc
CFLAGS = -Wall -O2
TARGET = test
SOURCE = test.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild
