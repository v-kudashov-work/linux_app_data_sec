// app_data_sec_watchdog_zenity.c
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

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================

#define PROCESS_NAME "app_data_sec_loader"
#define SERVICE_NAME "/usr/local/bin/app_data_sec_loader"

#define PROCESS_PATH_DEFAULT "app_data_sec_loader"

#define CHECK_INTERVAL 10           // Проверка каждые 10 секунд
#define RESTART_DELAY 2
#define MAX_RESTARTS 3
#define DIALOG_TIMEOUT 0
#define WAIT_FOR_FILE 1             // Ждать появления файла

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
// ПОКАЗ ОШИБКИ ЧЕРЕЗ ZENITY
// ============================================================================

static void show_error_zenity_blocking(const char *message) {
    char cmd[4096];
    char escaped_msg[4096];
    char *src = (char*)message;
    char *dst = escaped_msg;

    while (*src && dst - escaped_msg < sizeof(escaped_msg) - 3) {
        if (*src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    if (DIALOG_TIMEOUT > 0) {
        snprintf(cmd, sizeof(cmd),
                 "timeout %d zenity --error --title=\"APP DATA SEC - ERROR\" --text=\"%s\" --width=500 --height=300 2>/dev/null",
                 DIALOG_TIMEOUT, escaped_msg);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "zenity --error --title=\"APP DATA SEC - ERROR\" --text=\"%s\" --width=500 --height=300 2>/dev/null",
                 escaped_msg);
    }

    log_message(LOG_INFO, "Showing error dialog (waiting for user to close)");
    system(cmd);
    log_message(LOG_INFO, "User closed error dialog");
}

static void show_info_zenity_blocking(const char *message) {
    char cmd[4096];
    char escaped_msg[4096];
    char *src = (char*)message;
    char *dst = escaped_msg;

    while (*src && dst - escaped_msg < sizeof(escaped_msg) - 3) {
        if (*src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    if (DIALOG_TIMEOUT > 0) {
        snprintf(cmd, sizeof(cmd),
                 "timeout %d zenity --info --title=\"APP DATA SEC\" --text=\"%s\" --width=450 --height=200 2>/dev/null",
                 DIALOG_TIMEOUT, escaped_msg);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "zenity --info --title=\"APP DATA SEC\" --text=\"%s\" --width=450 --height=200 2>/dev/null",
                 escaped_msg);
    }

    log_message(LOG_INFO, "Showing info dialog");
    system(cmd);
}

static void show_error_console_blocking(const char *message) {
    printf("\n%s\n", message);
    printf("Press Enter to continue...\n");
    getchar();
}

// ============================================================================
// ФУНКЦИИ РАБОТЫ С ПРОЦЕССАМИ
// ============================================================================

static int is_file_executable(const char *path) {
    if (!path) return 0;
    return (access(path, X_OK) == 0);
}

static char* find_process_path(const char *process_name) {
    static char full_path[PATH_MAX];

    const char *standard_paths[] = {
        PROCESS_PATH_DEFAULT,
        "./app_data_sec_loader",
        "/usr/bin/app_data_sec_loader",
        "/usr/local/bin/app_data_sec_loader",
        "/usr/bin/app_data_sec_loader",
        "/opt/app_data_sec_loader",
        "/sbin/app_data_sec_loader",
        NULL
    };

    for (int i = 0; standard_paths[i] != NULL; i++) {
        if (access(standard_paths[i], X_OK) == 0) {
            if (realpath(standard_paths[i], full_path) != NULL) {
                return full_path;
            } else {
                strcpy(full_path, standard_paths[i]);
                return full_path;
            }
        }
    }

    char *path_env = getenv("PATH");
    if (path_env) {
        char *token;
        char path_copy[PATH_MAX];
        strncpy(path_copy, path_env, sizeof(path_copy) - 1);

        token = strtok(path_copy, ":");
        while (token != NULL) {
            snprintf(full_path, sizeof(full_path), "%s/%s", token, process_name);
            if (access(full_path, X_OK) == 0) {
                return full_path;
            }
            token = strtok(NULL, ":");
        }
    }

    return NULL;
}

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

static int start_process(const char *path) {
    if (!path || !is_file_executable(path)) {
        log_message(LOG_ERR, "Process file not found or not executable: %s", path ? path : "(null)");
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        log_message(LOG_ERR, "Failed to fork process: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        char *args[] = {(char*)path, NULL};
        execvp(path, args);
        log_message(LOG_ERR, "Failed to exec %s: %s", path, strerror(errno));
        exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    log_message(LOG_ERR, "Process %s exited with status: %d", path, WEXITSTATUS(status));
    return -1;
}

// ============================================================================
// ПРОВЕРКА СЕРВИСА
// ============================================================================

static int service_exists(const char *service_name) {
    char cmd[256];
    int result;
    snprintf(cmd, sizeof(cmd), "systemctl cat %s >/dev/null 2>&1", service_name);
    result = system(cmd);
    return (result == 0);
}

static int check_service_status(const char *service_name) {
    char cmd[256];
    char output[256] = {0};
    FILE *fp;
    int is_active = 0;

    snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>/dev/null", service_name);

    fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    if (fgets(output, sizeof(output), fp) != NULL) {
        size_t len = strlen(output);
        if (len > 0 && output[len-1] == '\n') {
            output[len-1] = '\0';
        }

        if (strcmp(output, "active") == 0) {
            is_active = 1;
        } else if (strcmp(output, "inactive") == 0 || strcmp(output, "failed") == 0) {
            is_active = 0;
        } else {
            is_active = 0;
        }
    }

    pclose(fp);
    return is_active;
}

static int restart_service(const char *service_name) {
    char cmd[256];
    int result;

    log_message(LOG_INFO, "Restarting service %s via systemctl...", service_name);
    snprintf(cmd, sizeof(cmd), "systemctl restart %s", service_name);
    result = system(cmd);

    if (result == 0) {
        log_message(LOG_INFO, "Service %s restarted successfully", service_name);
        return 0;
    } else {
        log_message(LOG_ERR, "Failed to restart service %s (exit code: %d)", service_name, result);
        return -1;
    }
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --path <path>    Path to app_data_sec_loader\n");
    fprintf(stderr, "  -i, --interval <sec> Check interval (default: 10)\n");
    fprintf(stderr, "  -d, --daemon         Run as daemon (no GUI)\n");
    fprintf(stderr, "  -z, --zenity         Use zenity for GUI notifications\n");
    fprintf(stderr, "  -c, --console        Use console notifications\n");
    fprintf(stderr, "  -s, --syslog         Log to syslog (enabled by default)\n");
    fprintf(stderr, "  -n, --no-syslog      Disable syslog logging\n");
    fprintf(stderr, "  -m, --max-restarts   Max restart attempts (default: 3)\n");
    fprintf(stderr, "  -w, --wait-file      Wait for file to appear (default: enabled)\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char **argv) {
    int check_interval = CHECK_INTERVAL;
    int run_daemon = 0;
    int use_zenity = 0;
    int use_console = 0;
    char *process_path = NULL;
    int restarts_attempted = 0;
    int max_restarts = MAX_RESTARTS;
    time_t last_check = 0;
    int first_check = 1;
    int service_available = 0;
    int dialog_shown = 0;
    int wait_for_file = WAIT_FOR_FILE;
    int file_found = 0;
    time_t file_wait_start = 0;
    int waiting_for_file = 0;

    syslog_enabled = 1;

    // Парсим аргументы
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            run_daemon = 1;
        } else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--zenity") == 0) {
            use_zenity = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--console") == 0) {
            use_console = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--syslog") == 0) {
            syslog_enabled = 1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-syslog") == 0) {
            syslog_enabled = 0;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--max-restarts") == 0) {
            max_restarts = atoi(argv[++i]);
            if (max_restarts < 1) max_restarts = 1;
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wait-file") == 0) {
            wait_for_file = 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--path") == 0) && i + 1 < argc) {
            process_path = argv[++i];
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
        use_zenity = 0;
        use_console = 0;
        log_message(LOG_INFO, "Running in daemon mode - GUI disabled");
    }

    // По умолчанию используем zenity если доступен
    if (!use_zenity && !use_console && !run_daemon) {
        if (system("which zenity >/dev/null 2>&1") == 0) {
            use_zenity = 1;
            log_message(LOG_INFO, "Using Zenity for GUI notifications");
        } else {
            use_console = 1;
            log_message(LOG_INFO, "Using console notifications");
        }
    }

    // Проверяем сервис
    if (service_exists(SERVICE_NAME)) {
        service_available = 1;
        log_message(LOG_INFO, "Systemd service '%s' found", SERVICE_NAME);
    }

    // Если путь не указан, ищем
    if (!process_path && !service_available) {
        process_path = find_process_path(PROCESS_NAME);
        if (process_path) {
            log_message(LOG_INFO, "Found %s at: %s", PROCESS_NAME, process_path);
            file_found = 1;
        } else {
            log_message(LOG_WARNING, "Could not find %s, will wait for it", PROCESS_NAME);
            file_found = 0;
            waiting_for_file = 1;
            file_wait_start = time(NULL);
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
    if (service_available) {
        log_message(LOG_INFO, "Service: %s (systemd)", SERVICE_NAME);
    } else {
        log_message(LOG_INFO, "Process: %s", process_path ? process_path : "WAITING FOR FILE");
    }
    log_message(LOG_INFO, "Check interval: %d seconds", check_interval);
    log_message(LOG_INFO, "Wait for file: %s", wait_for_file ? "enabled" : "disabled");
    log_message(LOG_INFO, "Max restarts: %d", max_restarts);
    log_message(LOG_INFO, "GUI: %s", use_zenity ? "enabled" : "disabled");
    log_message(LOG_INFO, "========================================");

    // Если файл не найден и ожидание включено
    if (!service_available && !file_found && wait_for_file) {
        char msg[512];
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        log_message(LOG_WARNING, "File not found, waiting for it to appear...");

        if (!run_daemon) {
            snprintf(msg, sizeof(msg),
                     "APP DATA SEC - ОЖИДАНИЕ ФАЙЛА\n\n"
                     "Исполняемый файл '%s' не найден.\n\n"
                     "Время: %s\n\n"
                     "Watchdog будет ждать появления файла.\n"
                     "Проверка каждые %d секунд.\n\n"
                     "Как только файл появится, он будет автоматически загружен.\n"
                     "Нажмите OK для продолжения.",
                     PROCESS_NAME, time_str, check_interval);

            if (use_zenity) {
                show_info_zenity_blocking(msg);
            } else if (use_console) {
                show_error_console_blocking(msg);
            }
            dialog_shown = 1;
        }
    }

    // Основной цикл
    while (1) {
        time_t now = time(NULL);

        if (now - last_check >= check_interval) {
            int is_running = 0;

            // ============================================================
            // ЕСЛИ ФАЙЛ НЕ НАЙДЕН - ПЫТАЕМСЯ НАЙТИ ЗАНОВО
            // ============================================================
            if (!service_available && (!file_found || !is_file_executable(process_path))) {
                char *new_path = find_process_path(PROCESS_NAME);
                if (new_path) {
                    process_path = new_path;
                    file_found = 1;
                    waiting_for_file = 0;
                    log_message(LOG_INFO, "FOUND %s at: %s", PROCESS_NAME, process_path);

                    if (!run_daemon && use_zenity) {
                        char info_msg[512];
                        snprintf(info_msg, sizeof(info_msg),
                                 "APP DATA SEC\n\n"
                                 "Исполняемый файл '%s' найден!\n"
                                 "Путь: %s\n\n"
                                 "Будет выполнен автоматический запуск.",
                                 PROCESS_NAME, process_path);
                        show_info_zenity_blocking(info_msg);
                    }
                    dialog_shown = 0;

                    // Пытаемся сразу запустить
                    if (start_process(process_path) == 0) {
                        log_message(LOG_INFO, "SUCCESS: %s started after file appeared", PROCESS_NAME);
                        restarts_attempted = 0;
                        is_running = 1;
                    }
                } else {
                    // Файл всё ещё не найден
                    if (wait_for_file && !dialog_shown && !run_daemon) {
                        time_t elapsed = time(NULL) - file_wait_start;
                        char msg[512];
                        snprintf(msg, sizeof(msg),
                                 "APP DATA SEC - ОЖИДАНИЕ ФАЙЛА\n\n"
                                 "Исполняемый файл '%s' всё ещё не найден.\n\n"
                                 "Время ожидания: %d секунд\n"
                                 "Проверка каждые %d секунд.\n\n"
                                 "Файл будет автоматически загружен при появлении.",
                                 PROCESS_NAME, (int)elapsed, check_interval);

                        if (use_zenity) {
                            show_info_zenity_blocking(msg);
                        } else if (use_console) {
                            show_error_console_blocking(msg);
                        }
                        dialog_shown = 1;
                    }

                    last_check = now;
                    continue;
                }
            }

            // ============================================================
            // ПРОВЕРКА СТАТУСА
            // ============================================================
            if (service_available) {
                int service_status = check_service_status(SERVICE_NAME);
                if (service_status == 1) {
                    is_running = 1;
                } else if (service_status == 0) {
                    is_running = 0;
                } else {
                    is_running = is_process_running(PROCESS_NAME);
                }
            } else {
                is_running = is_process_running(PROCESS_NAME);
            }

            // ============================================================
            // ПЕРВАЯ ПРОВЕРКА
            // ============================================================
            if (first_check) {
                if (is_running) {
                    log_message(LOG_INFO, "Initial check: %s is RUNNING", PROCESS_NAME);
                } else {
                    log_message(LOG_WARNING, "Initial check: %s is NOT RUNNING", PROCESS_NAME);
                }
                first_check = 0;
            }

            // ============================================================
            // ЕСЛИ ПРОЦЕСС НЕ ЗАПУЩЕН
            // ============================================================
            if (!is_running) {
                char msg[512];
                time_t t = time(NULL);
                struct tm *tm_info = localtime(&t);
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                log_message(LOG_ERR, "CRITICAL: %s is not running!",
                            service_available ? SERVICE_NAME : PROCESS_NAME);

                if (!run_daemon && !dialog_shown) {
                    snprintf(msg, sizeof(msg),
                             "APP DATA SEC - КРИТИЧЕСКАЯ ОШИБКА\n\n"
                             "%s '%s' не запущен!\n"
                             "Время: %s\n\n"
                             "Нажмите OK для попытки перезапуска.",
                             service_available ? "Сервис" : "Процесс",
                             service_available ? SERVICE_NAME : PROCESS_NAME,
                             time_str);

                    if (use_zenity) {
                        show_error_zenity_blocking(msg);
                    } else if (use_console) {
                        show_error_console_blocking(msg);
                    }
                    dialog_shown = 1;
                }

                log_message(LOG_INFO, "Attempting restart...");
                sleep(RESTART_DELAY);

                int restart_result = -1;

                if (service_available) {
                    restart_result = restart_service(SERVICE_NAME);
                } else if (process_path && is_file_executable(process_path)) {
                    restart_result = start_process(process_path);
                } else {
                    log_message(LOG_ERR, "No valid method to restart %s", PROCESS_NAME);
                }

                if (restart_result == 0) {
                    log_message(LOG_INFO, "SUCCESS: %s restarted",
                                service_available ? SERVICE_NAME : PROCESS_NAME);
                    restarts_attempted = 0;
                    dialog_shown = 0;

                    if (!run_daemon && use_zenity) {
                        char info_msg[512];
                        snprintf(info_msg, sizeof(info_msg),
                                 "APP DATA SEC\n\n"
                                 "%s '%s' успешно перезапущен.\n"
                                 "Время: %s",
                                 service_available ? "Сервис" : "Процесс",
                                 service_available ? SERVICE_NAME : PROCESS_NAME,
                                 time_str);
                        show_info_zenity_blocking(info_msg);
                    }
                } else {
                    log_message(LOG_ERR, "FAILED: Could not restart %s",
                                service_available ? SERVICE_NAME : PROCESS_NAME);
                    restarts_attempted++;

                    if (restarts_attempted >= max_restarts) {
                        log_message(LOG_ERR, "CRITICAL: Failed to restart after %d attempts", max_restarts);

                        if (!run_daemon) {
                            char warn_msg[512];
                            snprintf(warn_msg, sizeof(warn_msg),
                                     "APP DATA SEC - КРИТИЧЕСКАЯ ОШИБКА\n\n"
                                     "Не удалось перезапустить '%s' после %d попыток.\n\n"
                                     "Пожалуйста, запустите %s вручную.\n"
                                     "Нажмите OK для продолжения мониторинга.",
                                     service_available ? SERVICE_NAME : PROCESS_NAME,
                                     max_restarts,
                                     service_available ? "сервис" : "процесс");

                            if (use_zenity) {
                                show_error_zenity_blocking(warn_msg);
                            } else if (use_console) {
                                show_error_console_blocking(warn_msg);
                            }
                        }
                        restarts_attempted = 0;
                    }
                }
            } else {
                if (restarts_attempted > 0) {
                    log_message(LOG_INFO, "%s is running again",
                                service_available ? SERVICE_NAME : PROCESS_NAME);
                    restarts_attempted = 0;
                }
                dialog_shown = 0;
            }

            last_check = now;
        }

        sleep(1);
    }

    return 0;
}
