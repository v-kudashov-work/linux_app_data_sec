# Существующий Makefile с добавленным watchdog

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lm

# Основные цели
TARGETS = app_data_sec_loader app_data_sec_merge_config app_data_sec_watchdog

# Исходники
LOADER_SRC = app_data_sec_loader.c
MERGE_SRC = ./merge_config/app_data_sec_merge_config.c
WATCHDOG_SRC = app_data_sec_watchdog_zenity.c

# BPF компиляция
CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86
BPF_SRC = app_data_sec.bpf.c
BPF_OBJ = app_data_sec.bpf.o

# ==== Основные цели ====

all: $(TARGETS) $(BPF_OBJ)

app_data_sec_loader: $(LOADER_SRC)
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

app_data_sec_merge_config: $(MERGE_SRC)
	$(CC) $(CFLAGS) -o $@ $<

app_data_sec_watchdog: $(WATCHDOG_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

# ==== Watchdog только ====

watchdog: app_data_sec_watchdog

# ==== vmlinux.h ====

vmlinux.h:
	@if command -v bpftool > /dev/null; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "Warning: bpftool not found, using fallback vmlinux.h"; \
		touch vmlinux.h; \
	fi

# ==== Остальное ====

clean:
	rm -f $(TARGETS) $(BPF_OBJ) *.o

rebuild: clean all

.PHONY: all clean rebuild watchdog
