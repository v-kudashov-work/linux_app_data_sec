# makefile
CC = gcc
CLANG = clang
BPFTOOL = bpftool
CFLAGS = -Wall -O2
LDFLAGS = -lbpf -lelf -lz

TARGET = app_data_sec_loader
BPF_SRC = app_data_sec.bpf.c
BPF_OBJ = app_data_sec.bpf.o
SKEL_H = app_data_sec.skel.h

all: $(TARGET)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -mllvm -bpf-stack-size=1024 -c $(BPF_SRC) -o $(BPF_OBJ)

$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_H)

$(TARGET): app_data_sec_loader.c $(SKEL_H)
	$(CC) $(CFLAGS) -o $(TARGET) app_data_sec_loader.c $(LDFLAGS)

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL_H) vmlinux.h

install:
	@echo "Installing config file..."
	@if [ ! -f /etc/app_data_sec.conf ]; then \
		echo "# /etc/app_data_sec.conf" > /etc/app_data_sec.conf; \
		echo "# enable = yes|no" >> /etc/app_data_sec.conf; \
		echo "# protect <path> [allowed_prog1] [allowed_prog2] ..." >> /etc/app_data_sec.conf; \
		echo "" >> /etc/app_data_sec.conf; \
		echo "enable = yes" >> /etc/app_data_sec.conf; \
		echo "protect /home/vbox_user_vladimir/.test_app /bin/konsole" >> /etc/app_data_sec.conf; \
		echo "protect ~/.test_user_folder /bin/konsole" >> /etc/app_data_sec.conf; \
		echo "Config file created at /etc/app_data_sec.conf"; \
	fi

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean install run
