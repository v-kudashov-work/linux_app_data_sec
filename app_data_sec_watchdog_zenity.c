// app_data_sec_watchdog_zenity.c - Показывает диалог, пока не закроют
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/file.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================

#define PROCESS_NAME "app_data_sec_loader"
#define CHECK_INTERVAL 10            // Проверка каждые 10 секунд
#define LOCK_FILE "/var/lock/app_data_sec_watchdog.lock"
#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define DEBUGFS "/sys/kernel/debug"

// ============================================================================
// ЛОГИРОВАНИЕ
// ============================================================================

static int syslog_enabled = 1;

static void log_message(int priority, const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    printf("[%s] %s\n",
           priority == LOG_ERR ? "ERROR" :
           priority == LOG_WARNING ? "WARNING" :
           priority == LOG_INFO ? "INFO" : "DEBUG",
           buffer);
    fflush(stdout);

    if (syslog_enabled) {
        openlog("app_data_sec_watchdog", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog(priority, "%s", buffer);
        closelog();
    }
}

// ============================================================================
// БЛОКИРОВКА ОТ ПОВТОРНОГО ЗАПУСКА
// ============================================================================

static int check_single_instance(void) {
    int fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        log_message(LOG_ERR, "Failed to open lock file: %s", strerror(errno));
        return 0;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        log_message(LOG_ERR, "Another instance of watchdog is already running");
        close(fd);
        return 0;
    }

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    write(fd, pid_str, strlen(pid_str));
    ftruncate(fd, strlen(pid_str));

    return 1;
}

// ============================================================================
// ПРОВЕРКА, ЗАПУЩЕН ЛИ ПРОЦЕСС
// ============================================================================

static int is_process_running(const char *process_name) {
    DIR *dir;
    struct dirent *entry;
    char path[256];
    char cmdline[256];
    FILE *fp;
    int found = 0;

    dir = opendir("/proc");
    if (!dir) return 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        if (!isdigit(entry->d_name[0])) continue;

        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        fp = fopen(path, "r");
        if (!fp) continue;

        if (fgets(cmdline, sizeof(cmdline), fp)) {
            if (strstr(cmdline, process_name) != NULL &&
                strstr(cmdline, "watchdog") == NULL) {
                found = 1;
            fclose(fp);
            break;
                }
        }
        fclose(fp);
    }
    closedir(dir);
    return found;
}

// ============================================================================
// ПРОВЕРКА TRACE_PIPE
// ============================================================================

static int ensure_trace_pipe_available(void) {
    struct stat st;

    if (stat(DEBUGFS, &st) != 0) {
        log_message(LOG_WARNING, "debugfs does not exist, mounting...");
        if (mount("none", DEBUGFS, "debugfs", 0, NULL) != 0) {
            log_message(LOG_ERR, "Failed to mount debugfs: %s", strerror(errno));
            return 0;
        }
        log_message(LOG_INFO, "debugfs mounted");
    }

    if (stat(TRACE_PIPE, &st) != 0) {
        log_message(LOG_ERR, "trace_pipe does not exist at %s", TRACE_PIPE);
        return 0;
    }

    if (access(TRACE_PIPE, R_OK) != 0) {
        log_message(LOG_ERR, "trace_pipe not readable: %s", strerror(errno));
        return 0;
    }

    return 1;
}

// ============================================================================
// ЧТЕНИЕ BPF ЛОГОВ
// ============================================================================

static FILE *trace_fp = NULL;

static int read_trace_pipe(char *buffer, int size) {
    if (!trace_fp) {
        trace_fp = fopen(TRACE_PIPE, "r");
        if (!trace_fp) {
            log_message(LOG_ERR, "Failed to open trace_pipe: %s", strerror(errno));
            return -1;
        }

        int fd = fileno(trace_fp);
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    if (fgets(buffer, size, trace_fp) != NULL) {
        return 1;
    }

    if (ferror(trace_fp)) {
        clearerr(trace_fp);
        fclose(trace_fp);
        trace_fp = NULL;
        return 0;
    }

    return 0;
}

// ============================================================================
// ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ЭКРАНИРОВАНИЯ
// ============================================================================

static void escape_text(const char *src, char *dst, size_t dst_size) {
    while (*src && (size_t)(dst - dst) < dst_size - 3) {
        if (*src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

// ============================================================================
// ПРОВЕРКА НАЛИЧИЯ GUI
// ============================================================================

static int has_yad(void) {
    return (system("which yad >/dev/null 2>&1") == 0);
}

static int has_zenity(void) {
    return (system("which zenity >/dev/null 2>&1") == 0);
}

// ============================================================================
// ПРОВЕРКА, ЗАКРЫТ ЛИ ДИАЛОГ
// ============================================================================

static int dialog_pid = -1;

static int is_dialog_running(void) {
    if (dialog_pid <= 0) {
        return 0;
    }

    // Проверяем, существует ли процесс
    if (kill(dialog_pid, 0) == 0) {
        return 1;
    }

    dialog_pid = -1;
    return 0;
}

// ============================================================================
// ПОКАЗ СООБЩЕНИЙ (БЛОКИРУЮЩИЙ - ждет закрытия)
// ============================================================================

static void show_dialog_blocking(const char *title, const char *message, int is_error) {
    char cmd[8192];
    char escaped_msg[4096];

    // Если диалог уже открыт - не показываем новый
    if (is_dialog_running()) {
        log_message(LOG_INFO, "Dialog already open, skipping new one");
        return;
    }

    escape_text(message, escaped_msg, sizeof(escaped_msg));

    const char *type = is_error ? "error" : "info";
    const char *bg = is_error ? "#CC0000" : "#0066CC";
    const char *fg = is_error ? "white" : "white";
    const char *icon = is_error ? "⚠️" : "ℹ️";

    char pid_str[32];

    if (has_yad()) {
        snprintf(cmd, sizeof(cmd),
                 "yad --%s "
                 "--title=\"%s\" "
                 "--text=\"<span foreground='%s' background='%s' font='14' weight='bold'>%s %s</span>\" "
                 "--width=600 --height=400 "
                 "--button=\"OK\":0 "
                 "--button-color=\"#4CAF50\" "
                 "--button-fore=\"white\" "
                 "2>/dev/null & echo $!",
                 type, title, fg, bg, icon, escaped_msg);
    } else if (has_zenity()) {
        snprintf(cmd, sizeof(cmd),
                 "GTK_THEME=Adwaita:dark zenity --%s "
                 "--title=\"%s\" "
                 "--text=\"<span foreground='%s' background='%s' font='14' weight='bold'>%s %s</span>\" "
                 "--width=550 --height=400 "
                 "--ok-label=\"  OK  \" "
                 "2>/dev/null & echo $!",
                 type, title, fg, bg, icon, escaped_msg);
    } else {
        printf("\n\033[41m\033[1;37m[%s]\033[0m\n", title);
        printf("\033[31m%s\033[0m\n", message);
        return;
    }

    log_message(LOG_INFO, "Showing dialog: %s", title);

    // Запускаем и получаем PID
    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(pid_str, sizeof(pid_str), fp) != NULL) {
            dialog_pid = atoi(pid_str);
            log_message(LOG_INFO, "Dialog started with PID: %d", dialog_pid);
        }
        pclose(fp);
    } else {
        log_message(LOG_WARNING, "Failed to show dialog");
    }
}

// ============================================================================
// ПОКАЗ ДИАЛОГА ОСТАНОВКИ LOADER
// ============================================================================

static void show_loader_stopped_dialog(void) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    char msg[512];
    snprintf(msg, sizeof(msg),
             "app_data_sec_loader НЕ ЗАПУЩЕН!\n\n"
             "Время: %s\n\n"
             "Пожалуйста, запустите сервис:\n"
             "sudo systemctl start app_data_sec_loader\n\n"
             "Или проверьте логи:\n"
             "sudo journalctl -u app_data_sec_loader",
             time_str);

    log_message(LOG_ERR, "Showing dialog: loader is not running");
    show_dialog_blocking("APP DATA SEC - CRITICAL ERROR", msg, 1);
}

// ============================================================================
// ПОКАЗ ДИАЛОГА ЗАПУСКА LOADER
// ============================================================================

static void show_loader_started_dialog(void) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    char msg[512];
    snprintf(msg, sizeof(msg),
             "✅ app_data_sec_loader ЗАПУЩЕН\n\n"
             "Время: %s\n"
             "Статус: Работает",
             time_str);

    log_message(LOG_INFO, "Showing dialog: loader is running");
    show_dialog_blocking("APP DATA SEC - INFO", msg, 0);
}

// ============================================================================
// ОБРАБОТКА СООБЩЕНИЙ ИЗ BPF
// ============================================================================

static char last_msg[4096] = {0};
static time_t last_msg_time = 0;

static void process_bpf_message(const char *line) {
    if (!line || line[0] == '\0') return;

    if (!strstr(line, "APP_DATA_SEC")) return;
    if (!strstr(line, "BLOCKED")) return;

    // Проверяем, открыт ли диалог с блокировкой
    if (is_dialog_running()) {
        log_message(LOG_INFO, "Dialog already open, skipping BPF message");
        return;
    }

    time_t now = time(NULL);
    if (strcmp(line, last_msg) == 0 && (now - last_msg_time) < 60) {
        return;
    }
    strncpy(last_msg, line, sizeof(last_msg) - 1);
    last_msg[sizeof(last_msg) - 1] = '\0';
    last_msg_time = now;

    char pid[16] = "unknown";
    char uid[16] = "unknown";
    char path[256] = "unknown";
    char comm[64] = "unknown";
    char reason[64] = "unknown";

    char *pid_ptr = strstr(line, "PID=");
    if (pid_ptr) sscanf(pid_ptr, "PID=%15s", pid);

    char *uid_ptr = strstr(line, "UID=");
    if (uid_ptr) sscanf(uid_ptr, "UID=%15s", uid);

    char *path_ptr = strstr(line, "PATH=");
    if (path_ptr) sscanf(path_ptr, "PATH=%255s", path);

    char *comm_ptr = strstr(line, "COMM=");
    if (comm_ptr) sscanf(comm_ptr, "COMM=%63s", comm);

    char *reason_ptr = strstr(line, "REASON=");
    if (reason_ptr) sscanf(reason_ptr, "REASON=%63s", reason);

    char msg[1024];
    snprintf(msg, sizeof(msg),
             "Доступ запрещен!\n\n"
             "Программа: %s\n"
             "Путь: %s\n"
             "PID: %s\n"
             "UID: %s\n"
             "Причина: %s",
             comm, path, pid, uid, reason);

    log_message(LOG_WARNING, "BLOCKED: %s (PID=%s, UID=%s, PATH=%s, REASON=%s)",
                comm, pid, uid, path, reason);

    show_dialog_blocking("APP DATA SEC - WARNING", msg, 0);
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Watchdog for app_data_sec - shows notifications\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemon         Run as daemon\n");
    fprintf(stderr, "  -i, --interval <sec> Check interval (default: 10)\n");
    fprintf(stderr, "  -s, --syslog         Log to syslog (enabled by default)\n");
    fprintf(stderr, "  -n, --no-syslog      Disable syslog logging\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char **argv) {
    // Проверка на повторный запуск
    if (!check_single_instance()) {
        fprintf(stderr, "ERROR: Another instance of watchdog is already running\n");
        return 1;
    }

    int check_interval = CHECK_INTERVAL;
    int run_daemon = 0;
    int trace_ready = 0;
    int was_running = -1;  // -1 = неизвестно, 0 = не запущен, 1 = запущен
    time_t last_check_time = 0;

    syslog_enabled = 1;

    // Парсим аргументы
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            run_daemon = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--syslog") == 0) {
            syslog_enabled = 1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-syslog") == 0) {
            syslog_enabled = 0;
        } else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0) && i + 1 < argc) {
            check_interval = atoi(argv[++i]);
            if (check_interval < 2) check_interval = 2;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Запуск в фоновом режиме
    if (run_daemon) {
        pid_t pid = fork();
        if (pid < 0) {
            log_message(LOG_ERR, "Failed to fork daemon: %s", strerror(errno));
            return 1;
        }
        if (pid > 0) {
            printf("Watchdog started in background (PID: %d)\n", pid);
            log_message(LOG_INFO, "Watchdog started in background (PID: %d)", pid);
            return 0;
        }
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    log_message(LOG_INFO, "========================================");
    log_message(LOG_INFO, "APP DATA SEC WATCHDOG");
    log_message(LOG_INFO, "========================================");
    log_message(LOG_INFO, "Check interval: %d seconds", check_interval);
    log_message(LOG_INFO, "========================================");

    // Проверяем trace_pipe
    trace_ready = ensure_trace_pipe_available();

    if (!trace_ready) {
        log_message(LOG_ERR, "trace_pipe NOT available!");
        log_message(LOG_ERR, "Try: sudo mount -t debugfs none /sys/kernel/debug");
    } else {
        log_message(LOG_INFO, "trace_pipe is available");
    }

    // Основной цикл
    char buffer[8192];

    while (1) {
        time_t now = time(NULL);

        // ============================================================
        // ПРОВЕРЯЕМ, ЗАПУЩЕН ЛИ LOADER (каждые check_interval секунд)
        // ============================================================
        if (now - last_check_time >= check_interval) {
            int is_running = is_process_running(PROCESS_NAME);
            last_check_time = now;

            // Если состояние изменилось
            if (is_running != was_running) {
                if (is_running) {
                    log_message(LOG_INFO, "app_data_sec_loader is RUNNING");
                    show_loader_started_dialog();
                } else {
                    log_message(LOG_WARNING, "app_data_sec_loader is NOT RUNNING");
                    show_loader_stopped_dialog();
                }
                was_running = is_running;
            }

            // ============================================================
            // ЕСЛИ LOADER НЕ ЗАПУЩЕН - ПОКАЗЫВАЕМ ДИАЛОГ (если закрыт)
            // ============================================================
            if (!is_running) {
                // Проверяем, закрыл ли пользователь диалог
                if (!is_dialog_running()) {
                    log_message(LOG_INFO, "Dialog was closed, showing again");
                    show_loader_stopped_dialog();
                }
            }
        }

        // ============================================================
        // ЧИТАЕМ BPF ЛОГИ (только если loader запущен)
        // ============================================================
        if (trace_ready && was_running == 1) {
            int ret = read_trace_pipe(buffer, sizeof(buffer));

            if (ret > 0) {
                char *newline = strchr(buffer, '\n');
                if (newline) *newline = '\0';

                if (strstr(buffer, "APP_DATA_SEC") && strstr(buffer, "BLOCKED")) {
                    process_bpf_message(buffer);
                }
            } else if (ret == -1) {
                log_message(LOG_WARNING, "Cannot read trace_pipe, will retry...");
                trace_ready = 0;
                if (trace_fp) {
                    fclose(trace_fp);
                    trace_fp = NULL;
                }
            }
        } else if (!trace_ready) {
            // Пытаемся восстановить trace_pipe
            trace_ready = ensure_trace_pipe_available();
            if (trace_ready) {
                log_message(LOG_INFO, "trace_pipe recovered");
            }
        }

        sleep(1); // Проверяем каждую секунду (но проверки статуса раз в check_interval)
    }

    return 0;
}
