#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <dirent.h>

#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define BUFFER_SIZE 8192
#define MAX_PID_LEN 16
#define MAX_MSG_LEN 8192
#define MAX_PROCESS_CHAIN 32

// Структура для хранения информации о процессе
typedef struct {
    pid_t pid;
    char exe_path[PATH_MAX];
    char cmdline[PATH_MAX];
    char comm[64];
} process_info_t;

// Функция для получения пути к исполняемому файлу по PID
static char* get_process_path(pid_t pid) {
    static char path[PATH_MAX];
    char proc_path[64];
    ssize_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    len = readlink(proc_path, path, sizeof(path) - 1);
    if (len < 0) {
        snprintf(path, sizeof(path), "unknown");
        return path;
    }

    path[len] = '\0';

    char *deleted = strstr(path, " (deleted)");
    if (deleted) {
        *deleted = '\0';
    }

    return path;
}

// Функция для получения командной строки процесса по PID
static char* get_process_cmdline(pid_t pid) {
    static char cmdline[PATH_MAX];
    char proc_path[64];
    FILE *fp;
    size_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        snprintf(cmdline, sizeof(cmdline), "unknown");
        return cmdline;
    }

    len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    if (len == 0) {
        snprintf(cmdline, sizeof(cmdline), "empty");
        return cmdline;
    }

    for (size_t i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    cmdline[len] = '\0';

    while (len > 0 && cmdline[len - 1] == ' ') {
        cmdline[len - 1] = '\0';
        len--;
    }

    return cmdline;
}

// Функция для получения имени процесса (comm)
static char* get_process_comm(pid_t pid) {
    static char comm[64];
    char proc_path[64];
    FILE *fp;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        snprintf(comm, sizeof(comm), "unknown");
        return comm;
    }

    if (fgets(comm, sizeof(comm), fp) == NULL) {
        snprintf(comm, sizeof(comm), "unknown");
    } else {
        // Удаляем перевод строки
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n') {
            comm[len-1] = '\0';
        }
    }

    fclose(fp);
    return comm;
}

// Функция для получения родительского PID
static pid_t get_parent_pid(pid_t pid) {
    char proc_path[64];
    FILE *fp;
    pid_t ppid = -1;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        return -1;
    }

    // Формат: pid (comm) state ppid ...
    int p;
    char state;
    char comm[256];
    if (fscanf(fp, "%d %s %c %d", &p, comm, &state, &ppid) == 4) {
        // Успешно
    }

    fclose(fp);
    return ppid;
}

// Функция для получения информации о процессе
static bool get_process_info(pid_t pid, process_info_t *info) {
    if (!info) {
        return false;
    }

    info->pid = pid;
    strncpy(info->exe_path, get_process_path(pid), PATH_MAX - 1);
    info->exe_path[PATH_MAX - 1] = '\0';

    strncpy(info->cmdline, get_process_cmdline(pid), PATH_MAX - 1);
    info->cmdline[PATH_MAX - 1] = '\0';

    strncpy(info->comm, get_process_comm(pid), sizeof(info->comm) - 1);
    info->comm[sizeof(info->comm) - 1] = '\0';

    return true;
}

// Рекурсивная функция для сбора цепочки процессов
static int collect_process_chain(pid_t pid, process_info_t *chain, int max_depth) {
    int depth = 0;
    pid_t current_pid = pid;
    pid_t prev_pid = 0;

    while (current_pid > 0 && depth < max_depth) {
        if (!get_process_info(current_pid, &chain[depth])) {
            break;
        }
        depth++;

        // Получаем родительский PID
        prev_pid = current_pid;
        current_pid = get_parent_pid(current_pid);

        // Если родительский PID равен текущему (ошибка) или меньше 0
        if (current_pid == prev_pid || current_pid < 0) {
            break;
        }

        // Если достигли init (PID 1)
        if (current_pid == 1) {
            if (depth < max_depth) {
                get_process_info(1, &chain[depth]);
                depth++;
            }
            break;
        }
    }

    return depth;
}

// Функция для форматирования цепочки процессов в строку
static void format_process_chain(process_info_t *chain, int depth, char *output, size_t output_size) {
    int pos = 0;

    // Выводим от корня (глубокий) к листу (текущий процесс)
    for (int i = depth - 1; i >= 0; i--) {
        if (pos >= output_size - 1) {
            break;
        }

        // Добавляем информацию о процессе
        int written = snprintf(output + pos, output_size - pos,
                               "[%d] %s (PID:%d)",
                               depth - i,
                               chain[i].comm[0] != '\0' ? chain[i].comm : chain[i].exe_path,
                               chain[i].pid);

        if (written < 0) {
            break;
        }

        pos += written;

        // Добавляем разделитель между процессами
        if (i > 0 && pos < output_size - 1) {
            output[pos++] = ' ';
            output[pos++] = '>';
            output[pos++] = ' ';
        }
    }

    output[pos] = '\0';
}

// Функция для безопасного обрезания строки
static void safe_truncate(char *str, size_t max_len) {
    size_t len = strlen(str);
    if (len >= max_len) {
        str[max_len - 4] = '.';
        str[max_len - 3] = '.';
        str[max_len - 2] = '.';
        str[max_len - 1] = '\0';
    }
}

// Функция для парсинга PID из строки лога
static pid_t extract_pid(const char *line) {
    const char *pid_str = NULL;
    const char *p = line;

    while (*p) {
        if (strncmp(p, "PID=", 4) == 0) {
            pid_str = p + 4;
            break;
        }
        p++;
    }

    if (!pid_str) {
        return -1;
    }

    pid_t pid = 0;
    while (*pid_str && isdigit(*pid_str)) {
        pid = pid * 10 + (*pid_str - '0');
        pid_str++;
    }

    return pid;
}

// Функция для обработки строки лога
static void process_log_line(char *line) {
    // Удаляем перевод строки
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
        line[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        return;
    }

    // Проверяем, что это наше сообщение
    if (strstr(line, "APP_DATA_SEC:") == NULL) {
        return;
    }

    // Извлекаем PID
    pid_t pid = extract_pid(line);

    // Формируем сообщение для syslog
    char syslog_msg[MAX_MSG_LEN];
    char chain_str[2048] = "";

    if (pid > 0) {
        // Собираем цепочку процессов
        process_info_t chain[MAX_PROCESS_CHAIN];
        int depth = collect_process_chain(pid, chain, MAX_PROCESS_CHAIN);

        // Форматируем цепочку
        format_process_chain(chain, depth, chain_str, sizeof(chain_str));

        // Получаем информацию о текущем процессе для дополнительных деталей
        process_info_t current_info;
        if (get_process_info(pid, &current_info)) {
            // Обрезаем слишком длинные строки
            if (strlen(current_info.exe_path) > 256) {
                safe_truncate(current_info.exe_path, 256);
            }
            if (strlen(current_info.cmdline) > 512) {
                safe_truncate(current_info.cmdline, 512);
            }

            // Формируем сообщение с полной информацией
            int written = snprintf(syslog_msg, sizeof(syslog_msg),
                                   "%s | CHAIN: %s | CURRENT: PID=%d EXE=%s CMDLINE=%s",
                                   line, chain_str, pid, current_info.exe_path, current_info.cmdline);

            if (written >= (int)sizeof(syslog_msg) - 1) {
                syslog_msg[sizeof(syslog_msg) - 4] = '.';
                syslog_msg[sizeof(syslog_msg) - 3] = '.';
                syslog_msg[sizeof(syslog_msg) - 2] = '.';
                syslog_msg[sizeof(syslog_msg) - 1] = '\0';
            }
        } else {
            snprintf(syslog_msg, sizeof(syslog_msg), "%s | CHAIN: %s (PID=%d)",
                     line, chain_str, pid);
        }
    } else {
        // Если PID не найден, выводим как есть
        snprintf(syslog_msg, sizeof(syslog_msg), "%s", line);
    }

    // Отправляем в syslog
    syslog(LOG_INFO, "%s", syslog_msg);
}

int main(int argc, char *argv[]) {
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    char line_buffer[BUFFER_SIZE];
    int line_pos = 0;

    // Открываем системный журнал
    openlog("app_data_sec_messages", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "App Data Sec Messages Reader started");
    syslog(LOG_INFO, "Reading from: %s", TRACE_PIPE);

    // Открываем trace_pipe
    fd = open(TRACE_PIPE, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open %s: %s", TRACE_PIPE, strerror(errno));
        closelog();
        return 1;
    }

    // Читаем и обрабатываем строки
    while (1) {
        bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';

            // Обрабатываем каждую строку
            for (int i = 0; i < bytes_read; i++) {
                if (buffer[i] == '\n') {
                    line_buffer[line_pos] = '\0';
                    if (line_pos > 0) {
                        process_log_line(line_buffer);
                    }
                    line_pos = 0;
                } else if (line_pos < sizeof(line_buffer) - 1) {
                    line_buffer[line_pos++] = buffer[i];
                }
            }

            // Если остались данные без перевода строки
            if (line_pos > 0 && bytes_read > 0 && buffer[bytes_read - 1] != '\n') {
                // Не завершаем строку, ждем продолжения
            }
        } else if (bytes_read < 0) {
            if (errno != EINTR) {
                syslog(LOG_ERR, "Read error: %s", strerror(errno));
                break;
            }
        }
    }

    close(fd);
    closelog();
    return 0;
}
