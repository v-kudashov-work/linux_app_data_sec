// app_data_sec_autoconfig.c - Отдельный сервис для автоконфигурации
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/file.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================
#define VERSION "0.5.5"
#define VERSION_DATE "2026-08-22"

#define AUTOCONFIG_DIR "/etc/app_data_sec.autoconfig"
#define AUTOCONFIG_TIMESTAMP "/etc/app_data_sec.autoconfig.timestamp"
//#define AUTOCONFIG_CHECK_INTERVAL 900  // 15 минут
#define AUTOCONFIG_CHECK_INTERVAL 30  // 15 минут
#define PID_FILE "/run/app_data_sec_autoconfig.pid"
#define CONFIG_PATH "/etc/app_data_sec.conf"
#define LOADER_PID_FILE "/run/app_data_sec_loader.pid"

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================
static volatile int keep_running = 1;

// ============================================================================
// ЛОГИРОВАНИЕ В SYSLOG
// ============================================================================
static void log_to_syslog(int priority, const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    openlog("app_data_sec_autoconfig", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(priority, "%s", buffer);
    closelog();
}

#define SYSLOG_ERR(fmt, ...) log_to_syslog(LOG_ERR, "[ERROR] " fmt, ##__VA_ARGS__)
#define SYSLOG_WARN(fmt, ...) log_to_syslog(LOG_WARNING, "[WARNING] " fmt, ##__VA_ARGS__)
#define SYSLOG_INFO(fmt, ...) log_to_syslog(LOG_INFO, "[INFO] " fmt, ##__VA_ARGS__)

// ============================================================================
// ФУНКЦИИ ПРОВЕРКИ АВТОКОНФИГУРАЦИИ
// ============================================================================

static int autoconfig_changed(void) {
    struct stat st;
    time_t current_mtime = 0;
    time_t saved_timestamp = 0;

    // Проверяем существование директории
    if (stat(AUTOCONFIG_DIR, &st) != 0) {
        SYSLOG_INFO("Auto-config directory not found: %s", AUTOCONFIG_DIR);
        return 0;
    }

    // Получаем текущее время изменения директории
    current_mtime = st.st_mtime;

    // Проверяем, есть ли .conf файлы в директории
    DIR *dir = opendir(AUTOCONFIG_DIR);
    if (!dir) {
        SYSLOG_WARN("Cannot open auto-config directory: %s", AUTOCONFIG_DIR);
        return 0;
    }

    int has_conf = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char *ext = strrchr(entry->d_name, '.');
        if (ext && strcmp(ext, ".conf") == 0) {
            has_conf = 1;
            break;
        }
    }
    closedir(dir);

    if (!has_conf) {
        SYSLOG_INFO("No .conf files in auto-config directory");
        return 0;
    }

    // Читаем сохранённое время
    FILE *fp = fopen(AUTOCONFIG_TIMESTAMP, "r");
    if (fp) {
        if (fscanf(fp, "%ld", &saved_timestamp) == 1) {
            SYSLOG_INFO("Saved timestamp: %ld, current: %ld", saved_timestamp, current_mtime);
        }
        fclose(fp);
    }

    // Если время изменилось или файл с временем не существует
    if (current_mtime != saved_timestamp) {
        // Сохраняем новое время
        fp = fopen(AUTOCONFIG_TIMESTAMP, "w");
        if (fp) {
            fprintf(fp, "%ld", current_mtime);
            fclose(fp);
            SYSLOG_INFO("Auto-config timestamp updated: %ld", current_mtime);
        }
        return 1;
    }

    return 0;
}

static pid_t find_running_loader_pid(void) {
    FILE *fp = fopen(LOADER_PID_FILE, "r");
    if (!fp) {
        return -1;
    }

    pid_t pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Проверяем, существует ли процесс
    if (pid > 0 && kill(pid, 0) == 0) {
        return pid;
    }

    return -1;
}

static int apply_autoconfig(void) {
    SYSLOG_INFO("Auto-config changed! Applying new configurations...");

    // Проверяем наличие merge_config
    const char *merge_config_paths[] = {
        "/usr/local/bin/app_data_sec_merge_config",
        "/usr/bin/app_data_sec_merge_config",
        "./app_data_sec_merge_config",
        NULL
    };

    char merge_cmd[PATH_MAX];
    int found = 0;

    for (int i = 0; merge_config_paths[i] != NULL; i++) {
        if (access(merge_config_paths[i], X_OK) == 0) {
            strcpy(merge_cmd, merge_config_paths[i]);
            found = 1;
            break;
        }
    }

    if (!found) {
        SYSLOG_ERR("app_data_sec_merge_config not found, cannot apply auto-config");
        return -1;
    }

    // Формируем команду с принудительным обновлением (-y)
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd),
             "/bin/bash -c 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin %s -m %s %s --autoconfig -y'",
             merge_cmd, CONFIG_PATH, AUTOCONFIG_DIR);

    SYSLOG_INFO("Running: %s", cmd);

    int result = system(cmd);
    if (result == -1) {
        SYSLOG_ERR("Failed to execute command: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(result)) {
        int exit_code = WEXITSTATUS(result);
        if (exit_code == 0) {
            SYSLOG_INFO("Auto-config applied successfully");

            // Перезапускаем загрузчик для применения изменений
            SYSLOG_INFO("Send to app_data_sec_loader changes signal...");

            pid_t running_pid = find_running_loader_pid();

            if (running_pid > 0) {
                SYSLOG_INFO("Sending SIGUSR1 to running process (PID: %d)", running_pid);
                if (kill(running_pid, SIGUSR1) == 0) {
                    SYSLOG_INFO("Signal sent successfully");

                } else {
                    SYSLOG_ERR("Failed to send signal to PID %d: %s",
                               running_pid, strerror(errno));
                }
            } else {
                SYSLOG_ERR("No running app_data_sec_loader process found");
            }

            return 0;
        } else {
            SYSLOG_ERR("Failed to apply auto-config (exit code: %d)", exit_code);
            return -1;
        }
    } else {
        SYSLOG_ERR("Failed to apply auto-config (unexpected status: %d)", result);
        return -1;
    }
}

// ============================================================================
// РАБОТА С PID ФАЙЛОМ
// ============================================================================

static int check_single_instance(void) {
    int fd;
    char pid_str[32];
    pid_t existing_pid = 0;

    fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        SYSLOG_ERR("Failed to open PID file %s: %s", PID_FILE, strerror(errno));
        return 0;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        FILE *fp = fopen(PID_FILE, "r");
        if (fp) {
            if (fscanf(fp, "%d", &existing_pid) == 1) {
                if (kill(existing_pid, 0) == 0) {
                    SYSLOG_ERR("Another instance is already running (PID: %d). Exiting.", existing_pid);
                    fclose(fp);
                    close(fd);
                    return 0;
                } else {
                    SYSLOG_WARN("PID file exists but process %d is dead. Overriding...", existing_pid);
                }
            }
            fclose(fp);
        }

        close(fd);
        fd = open(PID_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            SYSLOG_ERR("Failed to recreate PID file: %s", strerror(errno));
            return 0;
        }

        if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
            SYSLOG_ERR("Failed to lock PID file after recreate: %s", strerror(errno));
            close(fd);
            return 0;
        }
    }

    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(fd, 0) == -1) {
        SYSLOG_WARN("Failed to truncate PID file: %s", strerror(errno));
    }
    if (write(fd, pid_str, strlen(pid_str)) < 0) {
        SYSLOG_WARN("Failed to write PID to %s: %s", PID_FILE, strerror(errno));
    }

    SYSLOG_INFO("PID file created: %s (PID: %d)", PID_FILE, getpid());
    return 1;
}

static void remove_pid_file(void) {
    unlink(PID_FILE);
    SYSLOG_INFO("PID file removed: %s", PID_FILE);
}

// ============================================================================
// ОБРАБОТЧИК СИГНАЛОВ
// ============================================================================

static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        SYSLOG_INFO("Received signal %d, shutting down...", sig);
        keep_running = 0;
    }
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help      Show this help\n");
    fprintf(stderr, "  -v, --version   Show version\n");
    fprintf(stderr, "  --once          Run once and exit (for testing)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This service monitors %s for new .conf files\n", AUTOCONFIG_DIR);
    fprintf(stderr, "and automatically merges them into %s\n", CONFIG_PATH);
    fprintf(stderr, "After merging, it restarts app_data_sec_loader.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Check interval: %d seconds\n", AUTOCONFIG_CHECK_INTERVAL);
}

int main(int argc, char **argv) {
    int run_once = 0;

    // Проверка прав
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (UID 0)\n");
        fprintf(stderr, "Please use: sudo %s\n", argv[0]);
        return 1;
    }

    // Парсинг аргументов
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("app_data_sec_autoconfig v%s (%s)\n", VERSION, VERSION_DATE);
            return 0;
        }
        if (strcmp(argv[i], "--once") == 0) {
            run_once = 1;
        }
    }

    openlog("app_data_sec_autoconfig", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    // Проверка единственного экземпляра
    if (!run_once) {
        if (!check_single_instance()) {
            SYSLOG_ERR("Another instance is already running. Exiting.");
            closelog();
            return 1;
        }
        atexit(remove_pid_file);
    }

    // Устанавливаем обработчики сигналов
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    SYSLOG_INFO("APP DATA SEC AUTOCONFIG STARTING (PID: %d)", getpid());
    SYSLOG_INFO("Version: %s (%s)", VERSION, VERSION_DATE);
    SYSLOG_INFO("Monitoring: %s", AUTOCONFIG_DIR);
    SYSLOG_INFO("Target config: %s", CONFIG_PATH);
    SYSLOG_INFO("Check interval: %d seconds", AUTOCONFIG_CHECK_INTERVAL);

    if (run_once) {
        SYSLOG_INFO("Running once mode (--once)");

        if (autoconfig_changed()) {
            SYSLOG_INFO("Auto-config changed, applying...");
            apply_autoconfig();
        } else {
            SYSLOG_INFO("No changes detected");
        }

        SYSLOG_INFO("APP DATA SEC AUTOCONFIG EXITING (once mode)");
        closelog();
        return 0;
    }

    // Основной цикл
    time_t last_check = time(NULL) - AUTOCONFIG_CHECK_INTERVAL - 100;

    while (keep_running) {
        time_t now = time(NULL);

        if (now - last_check >= AUTOCONFIG_CHECK_INTERVAL) {
            SYSLOG_INFO("Checking for auto-config changes...");

            if (autoconfig_changed()) {
                SYSLOG_INFO("Auto-config changed, applying...");
                apply_autoconfig();
            } else {
                SYSLOG_INFO("No changes detected");
            }

            last_check = now;
        }

        // Ждём с проверкой сигналов
        if (keep_running) {
            sleep(5);
        }
    }

    SYSLOG_INFO("APP DATA SEC AUTOCONFIG EXITING");
    closelog();
    return 0;
}
