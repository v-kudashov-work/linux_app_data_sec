// app_data_sec_watchdog.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <gtk/gtk.h>

#define PROCESS_NAME "app_data_sec_loader"
#define CHECK_INTERVAL 600  // 10 минут в секундах
#define RESTART_DELAY 5     // Задержка перед перезапуском (сек)
#define MAX_RESTARTS 3      // Максимум перезапусков за цикл

// Глобальные переменные для GTK
GtkWidget *error_dialog = NULL;
int error_dialog_shown = 0;

// ============================================================================
// ФУНКЦИИ РАБОТЫ С ПРОЦЕССАМИ
// ============================================================================

// Проверка, запущен ли процесс
static int is_process_running(const char *process_name) {
    DIR *dir;
    struct dirent *entry;
    char path[256];
    char cmdline[256];
    FILE *fp;
    int found = 0;

    dir = opendir("/proc");
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Проверяем, что это директория с числовым именем (PID)
        if (entry->d_type != DT_DIR) continue;
        if (!isdigit(entry->d_name[0])) continue;

        // Читаем cmdline процесса
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        fp = fopen(path, "r");
        if (!fp) continue;

        if (fgets(cmdline, sizeof(cmdline), fp)) {
            // Проверяем, содержит ли cmdline имя нашего процесса
            if (strstr(cmdline, process_name) != NULL) {
                // Исключаем сам watchdog
                if (strstr(cmdline, "watchdog") == NULL) {
                    found = 1;
                    fclose(fp);
                    break;
                }
            }
        }
        fclose(fp);
    }

    closedir(dir);
    return found;
}

// Запуск процесса
static int start_process(const char *path) {
    pid_t pid = fork();

    if (pid == -1) {
        return -1;
    }

    if (pid == 0) {
        // Дочерний процесс
        char *args[] = {
            (char*)path,
            NULL
        };
        execvp(path, args);
        // Если execvp вернулся, значит ошибка
        exit(1);
    }

    // Родительский процесс
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;  // Успешно запущен
    }

    return -1;  // Ошибка запуска
}

// Поиск пути к исполняемому файлу
static char* find_process_path(const char *process_name) {
    static char full_path[PATH_MAX];
    char *path_env = getenv("PATH");
    char *token;
    char path_copy[PATH_MAX];

    if (!path_env) {
        return NULL;
    }

    strncpy(path_copy, path_env, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    token = strtok(path_copy, ":");
    while (token != NULL) {
        snprintf(full_path, sizeof(full_path), "%s/%s", token, process_name);
        if (access(full_path, X_OK) == 0) {
            return full_path;
        }
        token = strtok(NULL, ":");
    }

    // Проверяем текущую директорию
    if (access(process_name, X_OK) == 0) {
        return (char*)process_name;
    }

    // Проверяем /usr/local/bin
    snprintf(full_path, sizeof(full_path), "/usr/local/bin/%s", process_name);
    if (access(full_path, X_OK) == 0) {
        return full_path;
    }

    // Проверяем /opt
    snprintf(full_path, sizeof(full_path), "/opt/%s", process_name);
    if (access(full_path, X_OK) == 0) {
        return full_path;
    }

    return NULL;
}

// ============================================================================
// GTK ФУНКЦИИ ДЛЯ ОТОБРАЖЕНИЯ ОШИБКИ
// ============================================================================

// Обработчик закрытия окна
static void on_dialog_close(GtkWidget *widget, gpointer data) {
    gtk_widget_destroy(widget);
    error_dialog_shown = 0;
    error_dialog = NULL;

    // Завершаем цикл GTK
    gtk_main_quit();
}

// Функция для показа окна с ошибкой
static void show_error_dialog(const char *message) {
    // Если окно уже показано, не создаём новое
    if (error_dialog_shown) {
        return;
    }

    // Инициализируем GTK если ещё не инициализирован
    if (!gtk_init_check(NULL, NULL)) {
        // Если GTK недоступен, выводим в консоль
        printf("\n%s\n", message);
        printf("Press Enter to continue...\n");
        getchar();
        return;
    }

    error_dialog_shown = 1;

    // Создаём диалоговое окно
    error_dialog = gtk_message_dialog_new(
        NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_ERROR,
        GTK_BUTTONS_OK,
        "%s", message
    );

    gtk_window_set_title(GTK_WINDOW(error_dialog), "APP DATA SEC - ERROR");
    gtk_window_set_position(GTK_WINDOW(error_dialog), GTK_WIN_POS_CENTER);
    gtk_window_set_keep_above(GTK_WINDOW(error_dialog), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(error_dialog), FALSE);

    // Добавляем кнопку закрытия
    // gtk_dialog_add_button(GTK_DIALOG(error_dialog), "OK", GTK_RESPONSE_OK);

    // Устанавливаем обработчик закрытия
    g_signal_connect(error_dialog, "response", G_CALLBACK(on_dialog_close), NULL);

    // Показываем окно
    gtk_widget_show_all(error_dialog);

    // Запускаем цикл GTK (блокирует выполнение)
    gtk_main();
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --path <path>    Path to app_data_sec_loader (optional, auto-detect)\n");
    fprintf(stderr, "  -i, --interval <sec> Check interval in seconds (default: 600 = 10 min)\n");
    fprintf(stderr, "  -d, --daemon         Run as daemon (background)\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
}

int main(int argc, char **argv) {
    int check_interval = CHECK_INTERVAL;
    int run_daemon = 0;
    char *process_path = NULL;
    int opt;
    int restarts_attempted = 0;
    time_t last_check = 0;

    // Обработка аргументов командной строки
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            run_daemon = 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--path") == 0) && i + 1 < argc) {
            process_path = argv[++i];
        } else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0) && i + 1 < argc) {
            check_interval = atoi(argv[++i]);
            if (check_interval < 10) {
                fprintf(stderr, "Warning: Interval too small, using 10 seconds\n");
                check_interval = 10;
            }
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
            fprintf(stderr, "Failed to fork daemon\n");
            return 1;
        }
        if (pid > 0) {
            printf("Watchdog started in background (PID: %d)\n", pid);
            return 0;
        }
        // Дочерний процесс продолжает работу
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    // Определяем путь к процессу, если не указан
    if (!process_path) {
        process_path = find_process_path(PROCESS_NAME);
        if (!process_path) {
            fprintf(stderr, "Error: Could not find %s in PATH\n", PROCESS_NAME);
            fprintf(stderr, "Please specify path with -p option\n");
            return 1;
        }
    }

    printf("Watchdog started for: %s\n", process_path);
    printf("Check interval: %d seconds (%d minutes)\n", check_interval, check_interval / 60);
    printf("Log: /var/log/app_data_sec_watchdog.log\n");

    // Основной цикл
    while (1) {
        time_t now = time(NULL);

        // Проверяем каждые check_interval секунд
        if (now - last_check >= check_interval) {
            int is_running = is_process_running(PROCESS_NAME);

            if (!is_running) {
                char msg[512];
                time_t t = time(NULL);
                struct tm *tm_info = localtime(&t);
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                snprintf(msg, sizeof(msg),
                         "APP DATA SEC - CRITICAL ERROR\n\n"
                         "Process '%s' is not running!\n"
                         "Time: %s\n"
                         "Attempting to restart...\n\n"
                         "Please check the system logs for details.",
                         PROCESS_NAME, time_str);

                // Выводим в лог
                printf("[%s] ERROR: Process %s is not running\n", time_str, PROCESS_NAME);

                // Показываем окно с ошибкой
                show_error_dialog(msg);

                // Пытаемся перезапустить
                printf("[%s] Attempting to restart %s...\n", time_str, PROCESS_NAME);
                sleep(RESTART_DELAY);

                if (start_process(process_path) == 0) {
                    printf("[%s] SUCCESS: Process %s restarted\n", time_str, PROCESS_NAME);
                    restarts_attempted = 0;
                } else {
                    printf("[%s] FAILED: Could not restart %s\n", time_str, PROCESS_NAME);
                    restarts_attempted++;

                    if (restarts_attempted >= MAX_RESTARTS) {
                        char warn_msg[512];
                        snprintf(warn_msg, sizeof(warn_msg),
                                 "APP DATA SEC - CRITICAL\n\n"
                                 "Failed to restart '%s' after %d attempts.\n"
                                 "Please check the system and start the process manually.\n\n"
                                 "Path: %s",
                                 PROCESS_NAME, MAX_RESTARTS, process_path);

                        show_error_dialog(warn_msg);
                        restarts_attempted = 0;
                    }
                }
            }

            last_check = now;
        }

        // Спим 1 секунду для экономии ресурсов
        sleep(1);
    }

    return 0;
}
