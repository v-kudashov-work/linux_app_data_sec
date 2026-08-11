// app_data_sec_watchdog_zenity.c - Только мониторинг и уведомления (без перезапуска)
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
#include <sys/mount.h>
#include <fcntl.h>
#include <limits.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================

#define PROCESS_NAME "app_data_sec_loader"
#define CHECK_INTERVAL 10           // Проверка каждые 10 секунд
#define PID_FILE "/var/run/app_data_sec_watchdog.pid"
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
    if (write(fd, pid_str, strlen(pid_str)) < 0) {
        log_message(LOG_WARNING, "Failed to write PID to lock file");
    }
    if (ftruncate(fd, strlen(pid_str)) < 0) {
        log_message(LOG_WARNING, "Failed to truncate lock file");
    }

    return 1;
}

// ============================================================================
// ПРОВЕРКА, ЗАПУЩЕН ЛИ ПРОЦЕСС
// ============================================================================

static int is_process_running(const char *process_name) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];
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
// НАСТРОЙКА TRACE_PIPE
// ============================================================================

static int ensure_trace_pipe_available(void) {
    // Проверяем, существует ли debugfs
    struct stat st;
    if (stat(DEBUGFS, &st) != 0) {
        log_message(LOG_WARNING, "debugfs does not exist, trying to mount...");
        if (mount("none", DEBUGFS, "debugfs", 0, NULL) != 0) {
            log_message(LOG_ERR, "Failed to mount debugfs: %s", strerror(errno));
            return 0;
        }
        log_message(LOG_INFO, "debugfs mounted successfully");
    }

    // Проверяем, существует ли trace_pipe
    if (stat(TRACE_PIPE, &st) != 0) {
        log_message(LOG_ERR, "trace_pipe does not exist at %s", TRACE_PIPE);
        log_message(LOG_ERR, "Kernel may not have CONFIG_TRACING enabled");
        return 0;
    }

    // Проверяем права доступа
    if (access(TRACE_PIPE, R_OK) != 0) {
        log_message(LOG_ERR, "trace_pipe not readable: %s", strerror(errno));
        log_message(LOG_ERR, "Try: sudo chmod 644 %s", TRACE_PIPE);
        return 0;
    }

    log_message(LOG_INFO, "trace_pipe is available at %s", TRACE_PIPE);
    return 1;
}

// ============================================================================
// ЧТЕНИЕ BPF ЛОГОВ
// ============================================================================

static int read_trace_pipe(char *buffer, int size) {
    static FILE *fp = NULL;
    static int reinit_counter = 0;

    // Если файл уже открыт, пробуем читать
    if (fp) {
        if (fgets(buffer, size, fp) != NULL) {
            return 1;
        }
        // Если EOF или ошибка - переоткрываем
        if (feof(fp) || ferror(fp)) {
            fclose(fp);
            fp = NULL;
            log_message(LOG_WARNING, "trace_pipe closed, re-opening...");
            return 0;
        }
        return 0;
    }

    // Открываем trace_pipe
    fp = fopen(TRACE_PIPE, "r");
    if (!fp) {
        reinit_counter++;
        if (reinit_counter % 6 == 0) { // Каждые ~60 секунд
            log_message(LOG_ERR, "Failed to open trace_pipe: %s (attempt %d)",
                        strerror(errno), reinit_counter);
            // Пытаемся перемонтировать debugfs
            ensure_trace_pipe_available();
        }
        return -1;
    }

    // Устанавливаем неблокирующий режим
    int fd = fileno(fp);
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    reinit_counter = 0;
    log_message(LOG_INFO, "trace_pipe opened successfully");
    return 0;
}

// ============================================================================
// ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ЭКРАНИРОВАНИЯ
// ============================================================================

static void escape_zenity_text(const char *src, char *dst, size_t dst_size) {
    while (*src && (size_t)(dst - dst) < dst_size - 3) {
        if (*src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

// ============================================================================
// ПРОВЕРКА НАЛИЧИЯ YAD
// ============================================================================

static int has_yad(void) {
    return (system("which yad >/dev/null 2>&1") == 0);
}

static int has_zenity(void) {
    return (system("which zenity >/dev/null 2>&1") == 0);
}

// ============================================================================
// ПОКАЗ СООБЩЕНИЙ ЧЕРЕЗ YAD
// ============================================================================

static void show_warning_yad(const char *message) {
    char cmd[8192];
    char escaped_msg[4096];

    escape_zenity_text(message, escaped_msg, sizeof(escaped_msg));

    snprintf(cmd, sizeof(cmd),
             "yad --warning "
             "--title=\"APP DATA SEC - WARNING\" "
             "--text=\"<span foreground='black' background='#FFA500' font='14' weight='bold'>⚠️ %s</span>\" "
             "--width=550 --height=300 "
             "--button=\"OK\":0 "
             "--button-color=\"#4CAF50\" "
             "--button-fore=\"white\" "
             "--back=\"#FFA500\" "
             "--fore=\"black\" "
             "2>/dev/null",
             escaped_msg);

    log_message(LOG_INFO, "Showing warning dialog via yad");
    if (system(cmd) < 0) {
        log_message(LOG_WARNING, "Failed to run yad command");
    }
}

// ============================================================================
// ПОКАЗ СООБЩЕНИЙ ЧЕРЕЗ ZENITY
// ============================================================================

static void show_warning_zenity_blocking(const char *message) {
    char cmd[8192];
    char escaped_msg[4096];

    escape_zenity_text(message, escaped_msg, sizeof(escaped_msg));

    snprintf(cmd, sizeof(cmd),
             "GTK_THEME=Adwaita:dark zenity --warning "
             "--title=\"APP DATA SEC - WARNING\" "
             "--text=\"<span foreground='black' background='#FFA500' font='14' weight='bold'>⚠️ %s</span>\" "
             "--width=500 --height=300 "
             "--ok-label=\"  OK  \" "
             "2>/dev/null",
             escaped_msg);

    log_message(LOG_INFO, "Showing warning dialog via zenity");
    if (system(cmd) < 0) {
        log_message(LOG_WARNING, "Failed to run zenity command");
    }
}

// ============================================================================
// ПОКАЗ СООБЩЕНИЙ (ОБЩАЯ ФУНКЦИЯ)
// ============================================================================

static void show_warning_message(const char *message) {
    if (has_yad()) {
        show_warning_yad(message);
    } else if (has_zenity()) {
        show_warning_zenity_blocking(message);
    } else {
        printf("\n\033[43m\033[1;30m[APP DATA SEC WARNING]\033[0m\n");
        printf("\033[33m%s\033[0m\n", message);
    }
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

    // Проверка на дубликаты
    time_t now = time(NULL);
    if (strcmp(line, last_msg) == 0 && (now - last_msg_time) < 60) {
        return;
    }
    strncpy(last_msg, line, sizeof(last_msg) - 1);
    last_msg[sizeof(last_msg) - 1] = '\0';
    last_msg_time = now;

    // Парсим сообщение
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

    // Формируем сообщение для отображения
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

    // Показываем уведомление
    show_warning_message(msg);
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Watchdog for app_data_sec - shows notifications on access blocks\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -z, --zenity         Use zenity/yad for GUI notifications\n");
    fprintf(stderr, "  -c, --console        Use console notifications\n");
    fprintf(stderr, "  -i, --interval <sec> Check interval (default: 10)\n");
    fprintf(stderr, "  -d, --daemon         Run as daemon (no GUI)\n");
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
    int use_gui = 0;
    int use_console = 0;
    int first_check = 1;
    int trace_ready = 0;

    syslog_enabled = 1;

    // Парсим аргументы
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            run_daemon = 1;
        } else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--zenity") == 0) {
            use_gui = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--console") == 0) {
            use_console = 1;
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

    // В режиме демона отключаем GUI
    if (run_daemon) {
        use_gui = 0;
        use_console = 0;
        log_message(LOG_INFO, "Running in daemon mode - GUI disabled");
    }

    // Проверяем наличие GUI
    if (use_gui && !run_daemon) {
        if (has_yad() || has_zenity()) {
            if (has_yad()) {
                log_message(LOG_INFO, "Using yad for GUI notifications");
            } else {
                log_message(LOG_INFO, "Using zenity for GUI notifications");
            }
        } else {
            log_message(LOG_WARNING, "No GUI tool found (yad/zenity), falling back to console");
            use_console = 1;
            use_gui = 0;
        }
    }

    if (!use_gui && !use_console && !run_daemon) {
        if (has_yad() || has_zenity()) {
            use_gui = 1;
            if (has_yad()) {
                log_message(LOG_INFO, "Using yad for GUI notifications");
            } else {
                log_message(LOG_INFO, "Using zenity for GUI notifications");
            }
        } else {
            use_console = 1;
            log_message(LOG_INFO, "Using console notifications");
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
        if (chdir("/") < 0) {
            log_message(LOG_WARNING, "Failed to chdir to /");
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    log_message(LOG_INFO, "========================================");
    log_message(LOG_INFO, "APP DATA SEC WATCHDOG (MONITOR ONLY)");
    log_message(LOG_INFO, "========================================");
    log_message(LOG_INFO, "Check interval: %d seconds", check_interval);
    log_message(LOG_INFO, "GUI: %s", use_gui ? "enabled" : "disabled");
    log_message(LOG_INFO, "========================================");

    // Проверяем доступность trace_pipe
    log_message(LOG_INFO, "Checking trace_pipe availability...");
    trace_ready = ensure_trace_pipe_available();

    if (!trace_ready) {
        log_message(LOG_WARNING, "trace_pipe not available, will retry every %d seconds", check_interval);
        log_message(LOG_WARNING, "Check that kernel has CONFIG_TRACING and CONFIG_DEBUG_FS enabled");
    }

    // Основной цикл
    char buffer[4096];
    int consecutive_errors = 0;

    while (1) {
        // Проверяем, запущен ли app_data_sec_loader (только для информации)
        int is_running = is_process_running(PROCESS_NAME);

        if (first_check) {
            if (is_running) {
                log_message(LOG_INFO, "Initial check: %s is RUNNING", PROCESS_NAME);
            } else {
                log_message(LOG_WARNING, "Initial check: %s is NOT RUNNING (systemd will handle restart)",
                            PROCESS_NAME);
            }
            first_check = 0;
        }

        // Если trace_pipe недоступен, пытаемся восстановить
        if (!trace_ready) {
            trace_ready = ensure_trace_pipe_available();
            sleep(check_interval);
            continue;
        }

        // Читаем логи из trace_pipe
        int ret = read_trace_pipe(buffer, sizeof(buffer));

        if (ret > 0) {
            consecutive_errors = 0;
            char *newline = strchr(buffer, '\n');
            if (newline) *newline = '\0';

            // Проверяем, содержит ли строка APP_DATA_SEC и BLOCKED
            if (strstr(buffer, "APP_DATA_SEC") && strstr(buffer, "BLOCKED")) {
                process_bpf_message(buffer);
            }
        } else if (ret == -1) {
            consecutive_errors++;
            if (consecutive_errors > 10) {
                log_message(LOG_ERR, "Too many errors reading trace_pipe, will retry...");
                trace_ready = 0;
                consecutive_errors = 0;
                sleep(check_interval);
                continue;
            }
            sleep(1);
        } else {
            // ret == 0 - нет данных, просто ждем
            consecutive_errors = 0;
        }

        sleep(check_interval);
    }

    return 0;
}
