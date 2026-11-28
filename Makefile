# Существующий Makefile с добавленным watchdog

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lm

# Основные цели
TARGETS = app_data_sec_loader app_data_sec_merge_config app_data_sec_watchdog app_data_sec_autoconfig

# Исходники
LOADER_SRC = app_data_sec_loader.c
MERGE_SRC = ./merge_config/app_data_sec_merge_config.c
WATCHDOG_SRC = app_data_sec_watchdog_informer.c

# BPF компиляция
CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf -mcpu=v4 -D__TARGET_ARCH_x86 \
             -mllvm -bpf-stack-size=1024
#              -fno-unroll-loops
BPF_SRC = app_data_sec.bpf.c
BPF_OBJ = app_data_sec.bpf.o

UNPROTECT = app_data_sec_unprotect
UNPROTECT_SRC = app_data_sec_unprotect.c

AUTOCONFIG = app_data_sec_autoconfig
AUTOCONFIG_SRC = app_data_sec_autoconfig.c

# ==== Основные цели ====

all: $(TARGETS) $(BPF_OBJ) $(UNPROTECT) $(AUTOCONFIG)

app_data_sec_loader: $(LOADER_SRC)
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

app_data_sec_merge_config: $(MERGE_SRC)
	$(CC) $(CFLAGS) -o $@ $<

app_data_sec_watchdog: $(WATCHDOG_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(UNPROTECT): $(UNPROTECT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(AUTOCONFIG): $(AUTOCONFIG_SRC)
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -Wno-missing-declarations -c $< -o $@

# ==== Watchdog только ====

watchdog: app_data_sec_watchdog

# ==== vmlinux.h ====

vmlinux.h:
	@BPFTOOL=""; \
	for c in /usr/sbin/bpftool /usr/bin/bpftool /usr/lib/linux-tools/*/bpftool; do \
		if [ -x "$$c" ]; then BPFTOOL="$$c"; break; fi; \
	done; \
	if command -v bpftool >/dev/null 2>&1; then BPFTOOL="$$($(BPF_CLANG) -E /dev/null >/dev/null 2>&1; command -v bpftool)"; fi; \
	if [ -z "$$BPFTOOL" ] && command -v bpftool >/dev/null 2>&1; then BPFTOOL=bpftool; fi; \
	if [ -n "$$BPFTOOL" ] && [ -f /sys/kernel/btf/vmlinux ]; then \
		"$$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "ERROR: bpftool not found or /sys/kernel/btf/vmlinux missing"; \
		echo "  Ubuntu/Debian: sudo apt install linux-tools-generic"; \
		echo "  Fedora: sudo dnf install bpftool"; \
		exit 1; \
	fi

# ==== Остальное ====

clean:
	rm -f $(TARGETS) $(BPF_OBJ) $(UNPROTECT) $(AUTOCONFIG) *.o

rebuild: clean all

.PHONY: all clean rebuild watchdog
