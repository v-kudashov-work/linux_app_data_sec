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

#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define BUFFER_SIZE 8192
#define MAX_PID_LEN 16
#define MAX_MSG_LEN 8192

// Функция для получения пути к исполняемому файлу по PID
static char* get_process_path(pid_t pid) {
    static char path[PATH_MAX];
    char proc_path[64];
    ssize_t len;

    // Формируем путь к /proc/PID/exe
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    // Читаем symbolic link
    len = readlink(proc_path, path, sizeof(path) - 1);
    if (len < 0) {
        snprintf(path, sizeof(path), "unknown");
        return path;
    }

    path[len] = '\0';

    // Если путь содержит (deleted), обрезаем
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

    // Читаем cmdline (аргументы разделены '\0')
    len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    if (len == 0) {
        snprintf(cmdline, sizeof(cmdline), "empty");
        return cmdline;
    }

    // Заменяем нулевые байты на пробелы
    for (size_t i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    cmdline[len] = '\0';

    // Удаляем лишние пробелы в конце
    while (len > 0 && cmdline[len - 1] == ' ') {
        cmdline[len - 1] = '\0';
        len--;
    }

    return cmdline;
}

// Функция для парсинга PID из строки лога
static pid_t extract_pid(const char *line) {
    const char *pid_str = NULL;
    const char *p = line;

    // Ищем "PID="
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

    // Извлекаем число
    pid_t pid = 0;
    while (*pid_str && isdigit(*pid_str)) {
        pid = pid * 10 + (*pid_str - '0');
        pid_str++;
    }

    return pid;
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
    char *exe_path = NULL;
    char *cmdline = NULL;

    if (pid > 0) {
        // Получаем путь к исполняемому файлу
        exe_path = get_process_path(pid);
        cmdline = get_process_cmdline(pid);

        // Обрезаем слишком длинные строки
        if (strlen(exe_path) > 256) {
            safe_truncate(exe_path, 256);
        }
        if (strlen(cmdline) > 512) {
            safe_truncate(cmdline, 512);
        }

        // Формируем сообщение с информацией о процессе
        int written = snprintf(syslog_msg, sizeof(syslog_msg),
                               "%s | PROCESS: PID=%d EXE=%s CMDLINE=%s",
                               line, pid, exe_path, cmdline);

        // Если snprintf обрезал сообщение, добавляем многоточие
        if (written >= (int)sizeof(syslog_msg) - 1) {
            syslog_msg[sizeof(syslog_msg) - 4] = '.';
            syslog_msg[sizeof(syslog_msg) - 3] = '.';
            syslog_msg[sizeof(syslog_msg) - 2] = '.';
            syslog_msg[sizeof(syslog_msg) - 1] = '\0';
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
