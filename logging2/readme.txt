3. Сборка и запуск
Нужны: clang, libbpf, bpftool, ядро с BTF и CONFIG_BPF_LSM=y.

# 1. Если ещё нет vmlinux.h:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Компилируем BPF-объект
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
      -c log_dir_access.bpf.c -o log_dir_access.bpf.o

# 3. Генерируем скелетон
bpftool gen skeleton log_dir_access.bpf.o > log_dir_access.skel.h

# 4. Собираем загрузчик
gcc -O2 -Wall -o log_dir_access log_dir_user.c -lbpf

# 5. Запускаем от root
sudo ./log_dir_access
В другом терминале смотрим логи:

sudo cat /sys/kernel/tracing/trace_pipe
