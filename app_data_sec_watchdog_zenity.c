// app_data_sec_watchdog_zenity.c - Создает файл на рабочем столе при ошибках
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
#include <pwd.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================

#define PROCESS_NAME "app_data_sec_loader"
#define CHECK_INTERVAL 9
#define LOCK_FILE "/var/lock/app_data_sec_watchdog.lock"
#define DESKTOP_FILE_NAME "app_data_sec_errors.txt"
#define MAX_USERS 100
#define MAX_PATH_LEN 4096

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

    ssize_t written = write(fd, pid_str, strlen(pid_str));
    if (written < 0) {
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
// ПОИСК ДОМАШНИХ ДИРЕКТОРИЙ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ
// ============================================================================

static void get_all_user_homes(char homes[MAX_USERS][PATH_MAX], int *count) {
    struct passwd *pw;
    *count = 0;

    setpwent();
    while ((pw = getpwent()) != NULL && *count < MAX_USERS) {
        if (pw->pw_uid < 1000) continue;
        if (!pw->pw_dir || pw->pw_dir[0] != '/') continue;

        struct stat st;
        if (stat(pw->pw_dir, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;

        strncpy(homes[*count], pw->pw_dir, PATH_MAX - 1);
        homes[*count][PATH_MAX - 1] = '\0';
        (*count)++;
    }
    endpwent();
}

// ============================================================================
// ПОИСК ДИРЕКТОРИИ РАБОЧЕГО СТОЛА (с подавлением предупреждений)
// ============================================================================

static int find_desktop_directory(const char *home, char *desktop_path, size_t size) {
    const char *paths[] = {
        "/Desktop",
        "/Рабочий стол",
        "/Рабочий стол",
        "/桌面",
        "/Desk",
        NULL
    };

    // Используем snprintf с явным ограничением
    for (int i = 0; paths[i] != NULL; i++) {
        int ret = snprintf(desktop_path, size, "%s%s", home, paths[i]);
        if (ret < 0 || (size_t)ret >= size) {
            // Путь не помещается в буфер - пропускаем
            continue;
        }
        struct stat st;
        if (stat(desktop_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return 1;
        }
    }

    // Пробуем найти через XDG_DESKTOP_DIR
    char xdg_file[MAX_PATH_LEN];
    int ret = snprintf(xdg_file, sizeof(xdg_file), "%s/.config/user-dirs.dirs", home);
    if (ret < 0 || (size_t)ret >= sizeof(xdg_file)) {
        return 0;
    }

    FILE *fp = fopen(xdg_file, "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "XDG_DESKTOP_DIR")) {
                char *eq = strchr(line, '=');
                if (eq) {
                    char *path = eq + 1;
                    while (*path == ' ' || *path == '"' || *path == '\'') path++;
                    char *end = path + strlen(path) - 1;
                    while (end > path && (*end == '\n' || *end == '\r' || *end == '"' || *end == '\'')) {
                        *end = '\0';
                        end--;
                    }

                    if (path[0] == '~' && path[1] == '/') {
                        ret = snprintf(desktop_path, size, "%s%s", home, path + 1);
                    } else if (path[0] == '/') {
                        ret = snprintf(desktop_path, size, "%s", path);
                    } else {
                        ret = snprintf(desktop_path, size, "%s/%s", home, path);
                    }

                    if (ret < 0 || (size_t)ret >= size) {
                        continue;
                    }

                    struct stat st;
                    if (stat(desktop_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                        fclose(fp);
                        return 1;
                    }
                }
            }
        }
        fclose(fp);
    }

    return 0;
}

// ============================================================================
// ЗАПИСЬ В ФАЙЛ НА РАБОЧЕМ СТОЛЕ (без смены владельца)
// ============================================================================

static void write_error_to_desktop(const char *message) {
    char homes[MAX_USERS][PATH_MAX];
    int user_count = 0;

    get_all_user_homes(homes, &user_count);

    if (user_count == 0) {
        log_message(LOG_WARNING, "No user home directories found");
        return;
    }

    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    for (int i = 0; i < user_count; i++) {
        char desktop_path[MAX_PATH_LEN];
        char file_path[MAX_PATH_LEN];

        if (!find_desktop_directory(homes[i], desktop_path, sizeof(desktop_path))) {
            log_message(LOG_DEBUG, "Desktop directory not found for %s", homes[i]);
            continue;
        }

        int ret = snprintf(file_path, sizeof(file_path), "%s/%s", desktop_path, DESKTOP_FILE_NAME);
        if (ret < 0 || (size_t)ret >= sizeof(file_path)) {
            log_message(LOG_WARNING, "File path too long for %s", desktop_path);
            continue;
        }

        // Проверяем, существует ли уже файл
        struct stat st;
        if (stat(file_path, &st) == 0) {
            log_message(LOG_DEBUG, "Error file already exists: %s", file_path);
            continue;
        }

        // Получаем владельца домашней директории (только для информации)
        if (stat(homes[i], &st) != 0) {
            log_message(LOG_WARNING, "Cannot stat home directory: %s", homes[i]);
            continue;
        }

        // Создаем файл напрямую от root (без смены владельца)
        FILE *fp = fopen(file_path, "w");
        if (!fp) {
            log_message(LOG_ERR, "Failed to create error file: %s", file_path);
            continue;
        }

        fprintf(fp, "⚠️ APP DATA SEC ERROR\n");
        fprintf(fp, "========================================\n");
        fprintf(fp, "%s\n", message);
        fprintf(fp, "========================================\n");
        fprintf(fp, "\n");
        fprintf(fp, "Файл создан: %s\n", time_str);
        fprintf(fp, "\n");
        fprintf(fp, "Файл создан от root, удалить можно только через sudo.\n");

        // Закрываем файл и проверяем результат
        int close_result = fclose(fp);
        if (close_result != 0) {
            log_message(LOG_ERR, "Failed to close error file: %s", file_path);
            unlink(file_path);
            continue;
        }
    }
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Watchdog for app_data_sec - creates desktop file on errors\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemon         Run as daemon\n");
    fprintf(stderr, "  -i, --interval <sec> Check interval (default: 10)\n");
    fprintf(stderr, "  -s, --syslog         Log to syslog (enabled by default)\n");
    fprintf(stderr, "  -n, --no-syslog      Disable syslog logging\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char **argv) {
    if (!check_single_instance()) {
        fprintf(stderr, "ERROR: Another instance of watchdog is already running\n");
        return 1;
    }

    int check_interval = CHECK_INTERVAL;
    int run_daemon = 0;
    int was_running = -1;
    time_t last_check_time = 0;
    int file_created = 0;

    syslog_enabled = 1;

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

    if (run_daemon) {
        pid_t pid = fork();
        if (pid < 0) {
            log_message(LOG_ERR, "Failed to fork daemon: %s", strerror(errno));
            return 1;
        }
        if (pid > 0) {
            printf("Watchdog started in background (PID: %d)\n", pid);
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
    log_message(LOG_INFO, "APP DATA SEC WATCHDOG");
    log_message(LOG_INFO, "========================================");
    log_message(LOG_INFO, "Check interval: %d seconds", check_interval);
    log_message(LOG_INFO, "Desktop file: %s on each user desktop (owned by root)", DESKTOP_FILE_NAME);

    while (1) {
        time_t now = time(NULL);

        if (now - last_check_time >= check_interval) {
            int is_running = is_process_running(PROCESS_NAME);
            last_check_time = now;

            if (is_running != was_running) {
                if (is_running) {
                    log_message(LOG_INFO, "app_data_sec_loader is RUNNING");
                } else {
                    log_message(LOG_WARNING, "app_data_sec_loader is NOT RUNNING");
                    file_created = 0;
                }
                was_running = is_running;
            }

            if (!is_running && !file_created) {
                time_t t = time(NULL);
                struct tm *tm_info = localtime(&t);
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                char msg[512];
                snprintf(msg, sizeof(msg),
                         "⚠️ app_data_sec_loader НЕ ЗАПУЩЕН!\n"
                         "Время обнаружения: %s\n\n"
                         "Чтобы запустить сервис:\n"
                         "  sudo systemctl start app_data_sec_loader\n\n"
                         "Проверить статус:\n"
                         "  sudo systemctl status app_data_sec_loader\n"
                         "  sudo journalctl -u app_data_sec_loader\n\n"
                         "Файл создан от root, удалить можно только через sudo.",
                         time_str);

                write_error_to_desktop(msg);
                file_created = 1;
            }
        }

        sleep(1);
    }

    return 0;
}
