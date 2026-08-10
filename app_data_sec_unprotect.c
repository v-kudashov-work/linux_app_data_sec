// app_data_sec_unprotect.c - С поддержкой ~
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>

#define MAX_LINE_LEN 1024
#define MAX_PATH_LEN 4096

// ============================================================================
// РАСКРЫТИЕ ~
// ============================================================================

static char* expand_path(const char *path) {
    if (!path) return NULL;

    // Если путь начинается с ~
    if (path[0] == '~') {
        static char expanded[MAX_PATH_LEN];

        // Если ~/ - раскрываем в домашнюю директорию текущего пользователя
        if (path[1] == '/' || path[1] == '\0') {
            const char *home = getenv("HOME");
            if (!home) {
                struct passwd *pw = getpwuid(getuid());
                if (pw) home = pw->pw_dir;
            }
            if (!home) {
                fprintf(stderr, "Error: Cannot determine home directory\n");
                return NULL;
            }

            if (path[1] == '\0') {
                snprintf(expanded, sizeof(expanded), "%s", home);
            } else {
                snprintf(expanded, sizeof(expanded), "%s%s", home, path + 1);
            }
            return expanded;
        }

        // Если ~username/ - раскрываем в домашнюю директорию пользователя
        if (path[1] != '/') {
            char *slash = strchr(path + 1, '/');
            int username_len;
            const char *subpath;

            if (slash) {
                username_len = slash - (path + 1);
                subpath = slash;
            } else {
                username_len = strlen(path + 1);
                subpath = "";
            }

            char username[256];
            if (username_len >= (int)sizeof(username)) {
                fprintf(stderr, "Error: Username too long\n");
                return NULL;
            }
            memcpy(username, path + 1, username_len);
            username[username_len] = '\0';

            struct passwd *pw = getpwnam(username);
            if (!pw) {
                fprintf(stderr, "Error: User not found: %s\n", username);
                return NULL;
            }

            snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
            return expanded;
        }
    }

    // Если путь не начинается с ~, возвращаем как есть
    return (char*)path;
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

static void trim(char *str) {
    if (!str || *str == '\0') return;

    char *start = str;
    while (*start == ' ' || *start == '\t') start++;

    if (*start == '\0') {
        *str = '\0';
        return;
    }

    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
        *end = '\0';
        end--;
    }

    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

static int starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return 0;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static int is_comment_or_empty(const char *line) {
    if (!line) return 1;
    while (*line == ' ' || *line == '\t') line++;
    return (*line == '\0' || *line == '#');
}

static int path_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0);
}

// ============================================================================
// ПОИСК ЗАЩИЩЕННОЙ ПАПКИ В КОНФИГЕ
// ============================================================================

static int find_protect_line(FILE *fp, const char *target_path, long *pos, char *found_line) {
    if (!fp || !target_path || !pos || !found_line) return -1;

    char line[MAX_LINE_LEN];
    long current_pos;

    rewind(fp);

    while (fgets(line, sizeof(line), fp)) {
        current_pos = ftell(fp);

        trim(line);
        if (is_comment_or_empty(line)) continue;

        if (starts_with(line, "protect")) {
            char *ptr = line + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') continue;

            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;

            char path[MAX_PATH_LEN];
            memcpy(path, ptr, path_len);
            path[path_len] = '\0';

            // Сравниваем с target_path (уже раскрытым)
            if (strcmp(path, target_path) == 0) {
                *pos = current_pos - strlen(line);
                strcpy(found_line, line);
                return 1;
            }
        }
    }

    return 0;
}

// ============================================================================
// УДАЛЕНИЕ ЗАПИСИ ИЗ КОНФИГА
// ============================================================================

static int remove_protect_entry(const char *config_path, const char *target_path) {
    if (!config_path || !target_path) {
        fprintf(stderr, "Error: NULL pointer passed\n");
        return -1;
    }

    // Раскрываем путь
    const char *expanded_target = expand_path(target_path);
    if (!expanded_target) {
        fprintf(stderr, "Error: Failed to expand path: %s\n", target_path);
        return -1;
    }

    if (!path_exists(config_path)) {
        fprintf(stderr, "Error: Config file not found: %s\n", config_path);
        return -1;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", config_path, strerror(errno));
        return -1;
    }

    long pos = 0;
    char found_line[MAX_LINE_LEN] = {0};
    int found = find_protect_line(fp, expanded_target, &pos, found_line);

    fclose(fp);

    if (!found) {
        fprintf(stderr, "Error: Protect entry not found for: %s (expanded: %s)\n",
                target_path, expanded_target);
        return -1;
    }

    printf("Found: %s", found_line);

    // Создаем резервную копию
    char backup[MAX_PATH_LEN];
    snprintf(backup, sizeof(backup), "%s.bak", config_path);

    if (rename(config_path, backup) != 0) {
        fprintf(stderr, "Error: Cannot create backup: %s\n", strerror(errno));
        return -1;
    }
    printf("Backup created: %s\n", backup);

    // Копируем все строки кроме найденной
    fp = fopen(backup, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open backup: %s\n", strerror(errno));
        return -1;
    }

    FILE *out = fopen(config_path, "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot write config: %s\n", strerror(errno));
        fclose(fp);
        return -1;
    }

    char line[MAX_LINE_LEN];
    long current_pos = 0;
    int skipped = 0;
    int copied = 0;

    rewind(fp);

    while (fgets(line, sizeof(line), fp)) {
        current_pos = ftell(fp);

        // Проверяем, не та ли это строка
        if (current_pos - strlen(line) == pos) {
            skipped++;
            printf("Removed: %s", line);
            continue;
        }

        fputs(line, out);
        copied++;
    }

    fclose(fp);
    fclose(out);

    printf("Config updated: %s (%d lines kept, %d removed)\n",
           config_path, copied, skipped);

    return 0;
}

// ============================================================================
// ВЫВОД СПИСКА ЗАЩИЩЕННЫХ ПАПОК
// ============================================================================

static int list_protected(const char *config_path) {
    if (!config_path) {
        fprintf(stderr, "Error: NULL pointer passed\n");
        return -1;
    }

    if (!path_exists(config_path)) {
        fprintf(stderr, "Error: Config file not found: %s\n", config_path);
        return -1;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", config_path, strerror(errno));
        return -1;
    }

    char line[MAX_LINE_LEN];
    int count = 0;

    printf("\nProtected folders:\n");
    printf("------------------\n");

    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (is_comment_or_empty(line)) continue;

        if (starts_with(line, "protect")) {
            char *ptr = line + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') continue;

            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;

            char path[MAX_PATH_LEN];
            memcpy(path, ptr, path_len);
            path[path_len] = '\0';

            printf("  %d. %s\n", ++count, path);
        }
    }

    fclose(fp);

    if (count == 0) {
        printf("  (none)\n");
    }
    printf("------------------\n");
    printf("Total: %d\n\n", count);

    return 0;
}

// ============================================================================
// ИНТЕРАКТИВНОЕ УДАЛЕНИЕ
// ============================================================================

static int interactive_remove(const char *config_path, const char *target_path) {
    if (!config_path || !target_path) {
        fprintf(stderr, "Error: NULL pointer passed\n");
        return -1;
    }

    // Раскрываем путь
    const char *expanded_target = expand_path(target_path);
    if (!expanded_target) {
        fprintf(stderr, "Error: Failed to expand path: %s\n", target_path);
        return -1;
    }

    if (!path_exists(config_path)) {
        fprintf(stderr, "Error: Config file not found: %s\n", config_path);
        return -1;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", config_path, strerror(errno));
        return -1;
    }

    long pos = 0;
    char found_line[MAX_LINE_LEN] = {0};
    int found = find_protect_line(fp, expanded_target, &pos, found_line);
    fclose(fp);

    if (!found) {
        fprintf(stderr, "Error: Protect entry not found for: %s (expanded: %s)\n",
                target_path, expanded_target);
        return -1;
    }

    printf("\nFound entry:\n");
    printf("  %s", found_line);
    printf("\nRemove this entry? (y/n): ");
    fflush(stdout);

    char answer[10];
    if (!fgets(answer, sizeof(answer), stdin)) {
        fprintf(stderr, "Error reading input\n");
        return -1;
    }

    if (answer[0] != 'y' && answer[0] != 'Y') {
        printf("Cancelled\n");
        return 0;
    }

    return remove_protect_entry(config_path, target_path);
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    if (!prog) prog = "app_data_sec_unprotect";
    fprintf(stderr, "Usage: %s [OPTIONS] <path>\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Remove protect entry from app_data_sec config.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --config <path>  Config file (default: /etc/app_data_sec.conf)\n");
    fprintf(stderr, "  -l, --list           List all protected folders\n");
    fprintf(stderr, "  -i, --interactive    Interactive mode (ask before remove)\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s /home/user/.config\n", prog);
    fprintf(stderr, "  %s ~/.config\n", prog);
    fprintf(stderr, "  %s -c /etc/app_data_sec.conf /home/user/.config\n", prog);
    fprintf(stderr, "  %s -l\n", prog);
    fprintf(stderr, "  %s -i ~/.config\n", prog);
}

int main(int argc, char **argv) {
    const char *config_path = "/etc/app_data_sec.conf";
    const char *target_path = NULL;
    int list_mode = 0;
    int interactive = 0;

    if (argc < 2) {
        fprintf(stderr, "Error: Missing arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!argv[i]) continue;

        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc && argv[i + 1]) {
                config_path = argv[++i];
            } else {
                fprintf(stderr, "Error: -c requires a path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list_mode = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            interactive = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            target_path = argv[i];
        }
    }

    // Режим списка
    if (list_mode) {
        return list_protected(config_path);
    }

    // Проверка пути
    if (!target_path) {
        fprintf(stderr, "Error: path to unprotect is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Проверяем существование конфига
    if (!path_exists(config_path)) {
        fprintf(stderr, "Error: Config file not found: %s\n", config_path);
        return 1;
    }

    // Интерактивный режим
    if (interactive) {
        return interactive_remove(config_path, target_path);
    }

    // Обычный режим
    return remove_protect_entry(config_path, target_path);
}
