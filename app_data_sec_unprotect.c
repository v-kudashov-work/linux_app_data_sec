// app_data_sec_unprotect.c - Удаление записей из конфига по списку из файла
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#define MAX_LINE_LEN 1024
#define MAX_PATH_LEN 4096
#define MAX_PATHS 1000

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
// ПАРСИНГ КОНФИГА И ПОЛУЧЕНИЕ СПИСКА ЗАЩИЩЕННЫХ ПУТЕЙ
// ============================================================================

static int get_protected_paths(const char *filename, char paths[MAX_PATHS][MAX_PATH_LEN], int *count) {
    if (!filename || !paths || !count) {
        fprintf(stderr, "Error: NULL pointer passed\n");
        return -1;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    char line[MAX_LINE_LEN];
    int line_num = 0;
    *count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        trim(line);
        if (is_comment_or_empty(line)) continue;

        if (starts_with(line, "protect")) {
            char *ptr = line + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                fprintf(stderr, "Warning: line %d: missing path after protect\n", line_num);
                continue;
            }

            if (*count >= MAX_PATHS) {
                fprintf(stderr, "Warning: line %d: max paths reached (%d)\n", line_num, MAX_PATHS);
                break;
            }

            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;

            memcpy(paths[*count], ptr, path_len);
            paths[*count][path_len] = '\0';
            (*count)++;
        }
    }

    fclose(fp);
    return 0;
}

// ============================================================================
// УДАЛЕНИЕ ЗАПИСЕЙ ИЗ КОНФИГА
// ============================================================================

static int remove_protect_entries(const char *main_config, const char *remove_config) {
    if (!main_config || !remove_config) {
        fprintf(stderr, "Error: NULL pointer passed\n");
        return -1;
    }

    if (!path_exists(main_config)) {
        fprintf(stderr, "Error: Main config not found: %s\n", main_config);
        return -1;
    }

    if (!path_exists(remove_config)) {
        fprintf(stderr, "Error: Remove config not found: %s\n", remove_config);
        return -1;
    }

    // Получаем список путей для удаления
    char remove_paths[MAX_PATHS][MAX_PATH_LEN];
    int remove_count = 0;

    printf("Reading remove config: %s\n", remove_config);
    if (get_protected_paths(remove_config, remove_paths, &remove_count) != 0) {
        fprintf(stderr, "Error: Failed to parse remove config\n");
        return -1;
    }

    if (remove_count == 0) {
        printf("No protect entries found in remove config, nothing to do\n");
        return 0;
    }

    printf("  Found %d paths to remove\n", remove_count);
    for (int i = 0; i < remove_count; i++) {
        printf("    %d. %s\n", i + 1, remove_paths[i]);
    }
    printf("\n");

    // Создаем резервную копию основного конфига
    char backup[MAX_PATH_LEN];
    snprintf(backup, sizeof(backup), "%s.bak", main_config);

    if (rename(main_config, backup) != 0) {
        fprintf(stderr, "Error: Cannot create backup: %s\n", strerror(errno));
        return -1;
    }
    printf("Backup created: %s\n", backup);

    // Открываем основной конфиг для чтения
    FILE *fp = fopen(backup, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open backup: %s\n", strerror(errno));
        return -1;
    }

    // Открываем новый конфиг для записи
    FILE *out = fopen(main_config, "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot write config: %s\n", strerror(errno));
        fclose(fp);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int removed = 0;
    int kept = 0;

    // Читаем построчно
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        trim(line_copy);

        if (is_comment_or_empty(line_copy)) {
            // Комментарии и пустые строки сохраняем
            fputs(line, out);
            kept++;
            continue;
        }

        // Проверяем enable строку
        if (starts_with(line_copy, "enable")) {
            // enable сохраняем как есть
            fputs(line, out);
            kept++;
            continue;
        }

        // Проверяем protect
        if (starts_with(line_copy, "protect")) {
            char *ptr = line_copy + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                // Пустой protect - сохраняем
                fputs(line, out);
                kept++;
                continue;
            }

            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;

            char path[MAX_PATH_LEN];
            memcpy(path, ptr, path_len);
            path[path_len] = '\0';

            // Проверяем, нужно ли удалить эту запись
            int should_remove = 0;
            for (int i = 0; i < remove_count; i++) {
                if (strcmp(path, remove_paths[i]) == 0) {
                    should_remove = 1;
                    break;
                }
            }

            if (should_remove) {
                removed++;
                printf("Removed: protect %s\n", path);
            } else {
                fputs(line, out);
                kept++;
            }
            continue;
        }

        // Все остальные строки сохраняем
        fputs(line, out);
        kept++;
    }

    fclose(fp);
    fclose(out);

    printf("\nSummary: %d entries removed, %d entries kept\n", removed, kept);

    if (removed == 0) {
        printf("No matching protect entries found in main config\n");
    }

    return 0;
}

// ============================================================================
// ВЫВОД СПИСКА ЗАЩИЩЕННЫХ ПАПОК В КОНФИГЕ
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

    printf("\nProtected folders in %s:\n", config_path);
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
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    if (!prog) prog = "app_data_sec_unprotect";
    fprintf(stderr, "Usage: %s [OPTIONS] <remove_config>\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Remove protect entries from main config using list from remove_config.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --config <path>  Main config file (default: /etc/app_data_sec.conf)\n");
    fprintf(stderr, "  -l, --list           List all protected folders in main config\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s /tmp/remove.conf\n", prog);
    fprintf(stderr, "  %s -c /etc/app_data_sec.conf /tmp/remove.conf\n", prog);
    fprintf(stderr, "  %s -l\n", prog);
}

int main(int argc, char **argv) {
    const char *main_config = "/etc/app_data_sec.conf";
    const char *remove_config = NULL;
    int list_mode = 0;

    if (argc < 2) {
        fprintf(stderr, "Error: Missing arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!argv[i]) continue;

        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc && argv[i + 1]) {
                main_config = argv[++i];
            } else {
                fprintf(stderr, "Error: -c requires a path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            remove_config = argv[i];
        }
    }

    // Режим списка
    if (list_mode) {
        return list_protected(main_config);
    }

    // Проверка пути к конфигу для удаления
    if (!remove_config) {
        fprintf(stderr, "Error: remove config file is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Проверяем существование основного конфига
    if (!path_exists(main_config)) {
        fprintf(stderr, "Error: Main config not found: %s\n", main_config);
        return 1;
    }

    // Проверяем существование конфига для удаления
    if (!path_exists(remove_config)) {
        fprintf(stderr, "Error: Remove config not found: %s\n", remove_config);
        return 1;
    }

    // Спрашиваем подтверждение
    printf("Main config: %s\n", main_config);
    printf("Remove config: %s\n", remove_config);
    printf("\nThis will REMOVE protect entries from main config.\n");
    printf("A backup will be created at: %s.bak\n", main_config);
    printf("\nContinue? (y/n): ");
    fflush(stdout);

    char answer[10];
    if (!fgets(answer, sizeof(answer), stdin)) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    if (answer[0] != 'y' && answer[0] != 'Y') {
        printf("Cancelled\n");
        return 0;
    }

    printf("\n");

    // Удаляем записи
    return remove_protect_entries(main_config, remove_config);
}
