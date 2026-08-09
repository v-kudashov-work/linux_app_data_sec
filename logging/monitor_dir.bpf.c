// monitor_dir.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Макрос для исключения ядер < 6.8, где bpf_path_d_path может быть недоступен
// В новых ядрах рекомендуется использовать bpf_path_d_path как более безопасную версию.
// В противном случае, используем (менее безопасный) bpf_d_path.
#if defined(CONFIG_DEBUG_INFO_BTF) && __has_builtin(__builtin_btf_type_id)
#define HAVE_BPF_PATH_D_PATH
#endif

char LICENSE[] SEC("license") = "GPL";

// Структура для передачи данных в пользовательское пространство через perf-буфер
struct event {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];  // Буфер для хранения пути
    int ret;
};

// Карта perf-буфера для отправки событий
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Глобальная переменная для хранения префикса целевой директории.
// Может быть установлена из пользовательского пространства.
const volatile char target_prefix[256] = {};

// Вспомогательная функция для безопасного получения пути файла
static __always_inline int get_path(struct file *f, char *buf, int len) {
    // Пытаемся использовать более новую и безопасную функцию,
    // которая помечена как KF_SLEEPABLE и требует BPF_F_SLEEPABLE,
    // поэтому мы используем SEC("lsm.s/file_open") для программы.
#ifdef HAVE_BPF_PATH_D_PATH
    return bpf_path_d_path(&f->f_path, buf, len);
#else
    // Fallback для старых ядер
    return bpf_d_path(&f->f_path, buf, len);
#endif
}

// LSM-программа, срабатывающая при каждом открытии файла
// Используем "lsm.s" для возможности вызова sleepable-функций, таких как bpf_path_d_path
SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char filename[256] = {};
    struct event event = {};

    // Получаем полный путь к файлу
    long ret = get_path(file, filename, sizeof(filename));
    if (ret < 0) {
        return 0; // Не удалось получить путь, игнорируем
    }

    // Проверяем, начинается ли путь с заданного префикса
    // Сравниваем только до длины префикса
    if (target_prefix[0] != '\0') {
        // Используем встроенную функцию для безопасного сравнения
        bool matches = true;
        #pragma unroll
        for (int i = 0; i < sizeof(target_prefix); i++) {
            if (target_prefix[i] == '\0') break;
            if (filename[i] != target_prefix[i]) {
                matches = false;
                break;
            }
        }
        if (!matches) {
            return 0; // Игнорируем файлы не из целевой папки
        }
    } else {
        return 0; // Целевая папка не задана
    }

    // Заполняем структуру события
    event.pid = pid;
    event.uid = uid;
    event.ret = 0; // В LSM-хуке file_open мы не имеем доступа к возвращаемому значению
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.filename, filename, sizeof(event.filename));

    // Отправляем событие в пользовательское пространство
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // Возвращаем 0, чтобы разрешить операцию.
    // Для блокировки доступа верните отрицательное значение (например, -EPERM).
    return 0;
}
