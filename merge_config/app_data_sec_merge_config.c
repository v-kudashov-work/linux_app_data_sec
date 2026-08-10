// merge_config.c - Утилита для слияния конфигов app_data_sec
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
#define MAX_ALLOWED 10

typedef struct {
    char path[MAX_PATH_LEN];
    char allowed[MAX_ALLOWED][MAX_PATH_LEN];
    int allowed_count;
    int is_template;  // 1 если путь начинается с ~
} protect_entry_t;

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

static void trim(char *str) {
    if (!str) return;

    char *start = str;
    while (*start == ' ' || *start == '\t') start++;

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
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static int is_comment_or_empty(const char *line) {
    while (*line == ' ' || *line == '\t') line++;
    return (*line == '\0' || *line == '#');
}

static int path_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// ============================================================================
// ПАРСИНГ КОНФИГА
// ============================================================================

static int parse_config(const char *filename, protect_entry_t *entries, int *count) {
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

        // Пропускаем enable
        if (starts_with(line, "enable")) continue;

        // Ищем protect
        if (starts_with(line, "protect")) {
            char *ptr = line + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                fprintf(stderr, "Warning: line %d: missing path after protect\n", line_num);
                continue;
            }

            // Извлекаем путь
            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;

            protect_entry_t *entry = &entries[*count];
            memset(entry, 0, sizeof(protect_entry_t));
            memcpy(entry->path, ptr, path_len);
            entry->path[path_len] = '\0';
            entry->is_template = (entry->path[0] == '~');

            // Парсим разрешенные программы
            ptr = path_end;
            while (*ptr) {
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (*ptr == '\0') break;

                char *arg_end = ptr;
                while (*arg_end && *arg_end != ' ' && *arg_end != '\t') arg_end++;

                size_t arg_len = arg_end - ptr;
                if (arg_len > 0 && entry->allowed_count < MAX_ALLOWED) {
                    memcpy(entry->allowed[entry->allowed_count], ptr, arg_len);
                    entry->allowed[entry->allowed_count][arg_len] = '\0';
                    entry->allowed_count++;
                }

                ptr = arg_end;
            }

            (*count)++;
        }
    }

    fclose(fp);
    return 0;
}

// ============================================================================
// ПОИСК В МАССИВЕ
// ============================================================================

static int find_entry(protect_entry_t *entries, int count, const char *path) {
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

static int is_allowed_exists(protect_entry_t *entry, const char *allowed_path) {
    for (int i = 0; i < entry->allowed_count; i++) {
        if (strcmp(entry->allowed[i], allowed_path) == 0) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// ЗАПИСЬ КОНФИГА
// ============================================================================

static int write_config(const char *filename, protect_entry_t *entries, int count, int enable) {
    // Создаем резервную копию
    char backup[MAX_PATH_LEN];
    snprintf(backup, sizeof(backup), "%s.bak", filename);

    if (path_exists(filename)) {
        if (rename(filename, backup) != 0) {
            fprintf(stderr, "Warning: Cannot create backup %s: %s\n", backup, strerror(errno));
        } else {
            printf("Backup created: %s\n", backup);
        }
    }

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot write %s: %s\n", filename, strerror(errno));
        return -1;
    }

    // Заголовок
    fprintf(fp, "# /etc/app_data_sec.conf\n");
    fprintf(fp, "# Конфигурация для eBPF блокировщика доступа к папкам\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# enable = yes|no - включает или отключает все ограничения\n");
    fprintf(fp, "# protect <path> [allowed_prog1] [allowed_prog2] ... - защищает папку\n");
    fprintf(fp, "#   path - путь к папке (можно использовать ~ для домашней директории)\n");
    fprintf(fp, "#   allowed_prog - абсолютный путь к программе, которая может обходить защиту\n");
    fprintf(fp, "\n");

    // enable
    fprintf(fp, "enable = %s\n\n", enable ? "yes" : "no");

    // Записи protect
    for (int i = 0; i < count; i++) {
        protect_entry_t *entry = &entries[i];

        fprintf(fp, "protect %s", entry->path);

        for (int j = 0; j < entry->allowed_count; j++) {
            fprintf(fp, " %s", entry->allowed[j]);
        }
        fprintf(fp, "\n");
    }

    fclose(fp);
    printf("Config written: %s (%d entries)\n", filename, count);
    return 0;
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [OPTIONS] <config_file>\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Merge protect entries from config_file into main config.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -m, --main <path>    Main config file (default: /etc/app_data_sec.conf)\n");
    fprintf(stderr, "  -d, --disable        Disable protection after merge (enable=no)\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s /tmp/new.conf\n", prog);
    fprintf(stderr, "  %s -m /etc/app_data_sec.conf /tmp/new.conf\n", prog);
    fprintf(stderr, "  %s -d /tmp/new.conf\n", prog);
}

int main(int argc, char **argv) {
    const char *main_config = "/etc/app_data_sec.conf";
    const char *merge_file = NULL;
    int enable = 1;

    // Парсинг аргументов
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--main") == 0) {
            if (i + 1 < argc) {
                main_config = argv[++i];
            } else {
                fprintf(stderr, "Error: -m requires a path\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--disable") == 0) {
            enable = 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            merge_file = argv[i];
        }
    }

    if (!merge_file) {
        fprintf(stderr, "Error: config file to merge is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Проверяем существование файла для слияния
    if (!path_exists(merge_file)) {
        fprintf(stderr, "Error: File not found: %s\n", merge_file);
        return 1;
    }

    printf("Main config: %s\n", main_config);
    printf("Merge config: %s\n", merge_file);
    printf("Enable: %s\n", enable ? "yes" : "no");
    printf("\n");

    // Парсим основной конфиг
    protect_entry_t main_entries[MAX_PATHS];
    int main_count = 0;

    if (path_exists(main_config)) {
        printf("Parsing main config...\n");
        if (parse_config(main_config, main_entries, &main_count) != 0) {
            fprintf(stderr, "Error: Failed to parse main config\n");
            return 1;
        }
        printf("  Found %d entries\n", main_count);
    } else {
        printf("Main config not found, will create new\n");
    }

    // Парсим конфиг для слияния
    protect_entry_t merge_entries[MAX_PATHS];
    int merge_count = 0;

    printf("Parsing merge config...\n");
    if (parse_config(merge_file, merge_entries, &merge_count) != 0) {
        fprintf(stderr, "Error: Failed to parse merge config\n");
        return 1;
    }
    printf("  Found %d entries\n", merge_count);

    if (merge_count == 0) {
        printf("No protect entries found in merge config, nothing to do\n");
        return 0;
    }

    // Слияние
    printf("\nMerging...\n");
    int added = 0;
    int updated = 0;
    int skipped = 0;

    for (int i = 0; i < merge_count; i++) {
        protect_entry_t *merge_entry = &merge_entries[i];

        int idx = find_entry(main_entries, main_count, merge_entry->path);

        if (idx >= 0) {
            // Запись существует - добавляем новые пути
            protect_entry_t *existing = &main_entries[idx];
            int new_allowed = 0;

            for (int j = 0; j < merge_entry->allowed_count; j++) {
                if (!is_allowed_exists(existing, merge_entry->allowed[j])) {
                    if (existing->allowed_count < MAX_ALLOWED) {
                        strcpy(existing->allowed[existing->allowed_count], merge_entry->allowed[j]);
                        existing->allowed_count++;
                        new_allowed++;
                    } else {
                        fprintf(stderr, "Warning: Max allowed programs reached for %s\n", existing->path);
                    }
                }
            }

            if (new_allowed > 0) {
                printf("  Updated: %s (+%d new allowed programs)\n", existing->path, new_allowed);
                updated++;
            } else {
                printf("  Skipped: %s (no new allowed programs)\n", existing->path);
                skipped++;
            }
        } else {
            // Новая запись
            if (main_count < MAX_PATHS) {
                memcpy(&main_entries[main_count], merge_entry, sizeof(protect_entry_t));
                main_count++;
                printf("  Added: %s (%d allowed programs)\n", merge_entry->path, merge_entry->allowed_count);
                added++;
            } else {
                fprintf(stderr, "Error: Max entries reached, cannot add %s\n", merge_entry->path);
            }
        }
    }

    printf("\nSummary: %d added, %d updated, %d skipped\n", added, updated, skipped);

    if (added == 0 && updated == 0) {
        printf("No changes to write\n");
        return 0;
    }

    // Записываем конфиг
    printf("\nWriting main config...\n");
    if (write_config(main_config, main_entries, main_count, enable) != 0) {
        fprintf(stderr, "Error: Failed to write config\n");
        return 1;
    }

    printf("\nDone!\n");
    printf("To apply changes: sudo systemctl restart app_data_sec_loader\n");

    return 0;
}
