# Makefile для run_script

CC = gcc
CFLAGS = -Wall -O2
TARGET = test
SOURCE = test.c

TARGET2 = test_mkdir
SOURCE2 = test_mkdir.c

all: $(TARGET) $(TARGET2)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)


$(TARGET2): $(SOURCE2)
	$(CC) $(CFLAGS) -o $(TARGET2) $(SOURCE2)

clean:
	rm -f $(TARGET) $(TARGET2)

rebuild: clean all

.PHONY: all clean rebuild
