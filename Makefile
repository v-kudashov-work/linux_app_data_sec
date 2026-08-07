# Makefile
CC = gcc
CLANG = clang
BPFTOOL = bpftool
CFLAGS = -Wall -O2
LDFLAGS = -lbpf -lelf -lz

all: loader

blocker.bpf.o: blocker.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/x86_64-linux-gnu \
		-c blocker.bpf.c -o blocker.bpf.o
	$(BPFTOOL) gen skeleton blocker.bpf.o > blocker.skel.h

loader: loader.c blocker.bpf.o
	$(CC) $(CFLAGS) -o loader loader.c $(LDFLAGS)

clean:
	rm -f loader blocker.bpf.o blocker.skel.h

.PHONY: all clean
