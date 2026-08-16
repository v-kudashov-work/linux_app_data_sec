// app_data_sec_merge_config.c - С поддержкой загрузки всех конфигов из папки
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#define MAX_LINE_LEN 1024
#define MAX_PATH_LEN 4096
#define MAX_PATHS 1000
#define MAX_ALLOWED 10
#define MAX_CONFIG_FILES 1000

typedef struct {
    char path[MAX_PATH_LEN];
    char allowed[MAX_ALLOWED][MAX_PATH_LEN];
    int allowed_count;
    int is_template;
} protect_entry_t;

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

static int is_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

static int is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

// ============================================================================
// ПОЛУЧЕНИЕ СПИСКА КОНФИГОВ ИЗ ПАПКИ
// ============================================================================

static int get_config_files(const char *dir_path, char files[MAX_CONFIG_FILES][PATH_MAX]) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Warning: Cannot open directory %s: %s\n", dir_path, strerror(errno));
        return 0;
    }

    while ((entry = readdir(dir)) != NULL && count < MAX_CONFIG_FILES) {
        if (entry->d_name[0] == '.') continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        if (!is_file(full_path)) continue;

        // Проверяем расширение .conf
        char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcmp(ext, ".conf") != 0) continue;

        // Используем snprintf для безопасного копирования
        snprintf(files[count], PATH_MAX, "%s", full_path);
        count++;
    }

    closedir(dir);

    // Сортируем файлы для предсказуемого порядка
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (strcmp(files[i], files[j]) > 0) {
                char tmp[PATH_MAX];
                strcpy(tmp, files[i]);
                strcpy(files[i], files[j]);
                strcpy(files[j], tmp);
            }
        }
    }

    return count;
}

// ============================================================================
// ПАРСИНГ КОНФИГА
// ============================================================================

static int parse_config(const char *filename, protect_entry_t **entries, int *count) {
    if (!filename || !entries || !count) {
        fprintf(stderr, "Error: NULL pointer passed to parse_config\n");
        return -1;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    // Выделяем память для записей
    *entries = calloc(MAX_PATHS, sizeof(protect_entry_t));
    if (!*entries) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        fclose(fp);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int line_num = 0;
    *count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        trim(line);
        if (is_comment_or_empty(line)) continue;

        if (starts_with(line, "enable")) continue;

        if (starts_with(line, "protect")) {
            char *ptr = line + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                fprintf(stderr, "Warning: line %d: missing path after protect\n", line_num);
                continue;
            }

            if (*count >= MAX_PATHS) {
                fprintf(stderr, "Warning: line %d: max entries reached (%d)\n", line_num, MAX_PATHS);
                break;
            }

            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= MAX_PATH_LEN) {
                path_len = MAX_PATH_LEN - 1;
                fprintf(stderr, "Warning: line %d: path too long, truncating\n", line_num);
            }

            protect_entry_t *entry = &(*entries)[*count];
            memset(entry, 0, sizeof(protect_entry_t));
            memcpy(entry->path, ptr, path_len);
            entry->path[path_len] = '\0';
            entry->is_template = (entry->path[0] == '~');

            ptr = path_end;
            while (*ptr) {
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (*ptr == '\0') break;

                char *arg_end = ptr;
                while (*arg_end && *arg_end != ' ' && *arg_end != '\t') arg_end++;

                size_t arg_len = arg_end - ptr;
                if (arg_len > 0 && entry->allowed_count < MAX_ALLOWED) {
                    if (arg_len >= MAX_PATH_LEN) {
                        arg_len = MAX_PATH_LEN - 1;
                    }
                    memcpy(entry->allowed[entry->allowed_count], ptr, arg_len);
                    entry->allowed[entry->allowed_count][arg_len] = '\0';
                    entry->allowed_count++;
                } else if (arg_len > 0) {
                    fprintf(stderr, "Warning: line %d: max allowed programs reached for %s\n",
                            line_num, entry->path);
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
    if (!entries || !path) return -1;

    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

static int is_allowed_exists(protect_entry_t *entry, const char *allowed_path) {
    if (!entry || !allowed_path) return 0;

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
    if (!filename || !entries) {
        fprintf(stderr, "Error: NULL pointer passed to write_config\n");
        return -1;
    }

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

    fprintf(fp, "# /etc/app_data_sec.conf\n");
    fprintf(fp, "# Конфигурация для eBPF блокировщика доступа к папкам\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# enable = yes|no - включает или отключает все ограничения\n");
    fprintf(fp, "# protect <path> [allowed_prog1] [allowed_prog2] ... - защищает папку\n");
    fprintf(fp, "#   path - путь к папке (можно использовать ~ для домашней директории)\n");
    fprintf(fp, "#   allowed_prog - абсолютный путь к программе, которая может обходить защиту\n");
    fprintf(fp, "\n");

    fprintf(fp, "enable = %s\n\n", enable ? "yes" : "no");

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
    if (!prog) prog = "app_data_sec_merge_config";
    fprintf(stderr, "Usage: %s [OPTIONS] <config_file_or_dir>\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Merge protect entries from config_file or all .conf files in directory.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -m, --main <path>    Main config file (default: /etc/app_data_sec.conf)\n");
    fprintf(stderr, "  -d, --disable        Disable protection after merge (enable=no)\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s /tmp/new.conf\n", prog);
    fprintf(stderr, "  %s /etc/app_data_sec.d/\n", prog);
    fprintf(stderr, "  %s -m /etc/app_data_sec.conf /tmp/new.conf\n", prog);
    fprintf(stderr, "  %s -m /etc/app_data_sec.conf /etc/app_data_sec.d/\n", prog);
}

int main(int argc, char **argv) {
    const char *main_config = "/etc/app_data_sec.conf";
    const char *source = NULL;
    int enable = 1;

    if (argc < 2) {
        fprintf(stderr, "Error: Missing arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!argv[i]) continue;

        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--main") == 0) {
            if (i + 1 < argc && argv[i + 1]) {
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
            source = argv[i];
        }
    }

    if (!source) {
        fprintf(stderr, "Error: config file or directory is required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!path_exists(source)) {
        fprintf(stderr, "Error: File or directory not found: %s\n", source);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (UID 0)\n");
        fprintf(stderr, "Please use: sudo %s\n", argv[0]);
        return 1;
    }

    // Определяем, файл это или директория
    int is_dir_mode = is_dir(source);

    printf("Main config: %s\n", main_config);
    if (is_dir_mode) {
        printf("Source directory: %s (all .conf files)\n", source);
    } else {
        printf("Source config: %s\n", source);
    }
    printf("Enable: %s\n", enable ? "yes" : "no");
    printf("\n");

    // Загружаем основной конфиг
    protect_entry_t *main_entries = NULL;
    int main_count = 0;

    if (path_exists(main_config)) {
        printf("Parsing main config...\n");
        if (parse_config(main_config, &main_entries, &main_count) != 0) {
            fprintf(stderr, "Error: Failed to parse main config\n");
            free(main_entries);
            return 1;
        }
        printf("  Found %d entries\n", main_count);
    } else {
        printf("Main config not found, will create new\n");
        main_entries = calloc(MAX_PATHS, sizeof(protect_entry_t));
        if (!main_entries) {
            fprintf(stderr, "Error: Failed to allocate memory\n");
            return 1;
        }
    }

    // Получаем список файлов для слияния
    char config_files[MAX_CONFIG_FILES][PATH_MAX];
    int file_count = 0;

    if (is_dir_mode) {
        file_count = get_config_files(source, config_files);
        if (file_count == 0) {
            printf("No .conf files found in directory: %s\n", source);
            free(main_entries);
            return 0;
        }
        printf("Found %d .conf files in directory\n", file_count);
        for (int i = 0; i < file_count; i++) {
            printf("  - %s\n", config_files[i]);
        }
        printf("\n");
    } else {
        strncpy(config_files[0], source, PATH_MAX - 1);
        config_files[0][PATH_MAX - 1] = '\0';
        file_count = 1;
    }

    // Парсим и сливаем все файлы
    int total_added = 0;
    int total_updated = 0;
    int total_skipped = 0;

    for (int f = 0; f < file_count; f++) {
        printf("--- Processing: %s ---\n", config_files[f]);

        protect_entry_t *merge_entries = NULL;
        int merge_count = 0;

        if (parse_config(config_files[f], &merge_entries, &merge_count) != 0) {
            fprintf(stderr, "Error: Failed to parse %s\n", config_files[f]);
            free(merge_entries);
            continue;
        }

        if (merge_count == 0) {
            printf("  No protect entries found, skipping\n");
            free(merge_entries);
            continue;
        }

        printf("  Found %d entries\n", merge_count);

        int file_added = 0;
        int file_updated = 0;
        int file_skipped = 0;

        for (int i = 0; i < merge_count; i++) {
            protect_entry_t *merge_entry = &merge_entries[i];
            int idx = find_entry(main_entries, main_count, merge_entry->path);

            if (idx >= 0) {
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
                    file_updated++;
                } else {
                    printf("  Skipped: %s (no new allowed programs)\n", existing->path);
                    file_skipped++;
                }
            } else {
                if (main_count < MAX_PATHS) {
                    memcpy(&main_entries[main_count], merge_entry, sizeof(protect_entry_t));
                    main_count++;
                    printf("  Added: %s (%d allowed programs)\n", merge_entry->path, merge_entry->allowed_count);
                    file_added++;
                } else {
                    fprintf(stderr, "Error: Max entries reached, cannot add %s\n", merge_entry->path);
                }
            }
        }

        free(merge_entries);

        total_added += file_added;
        total_updated += file_updated;
        total_skipped += file_skipped;

        printf("  Summary: +%d added, +%d updated, %d skipped\n", file_added, file_updated, file_skipped);
        printf("\n");
    }

    printf("=== Final Summary ===\n");
    printf("Total: %d added, %d updated, %d skipped\n", total_added, total_updated, total_skipped);

    if (total_added == 0 && total_updated == 0) {
        printf("No changes to write\n");
        free(main_entries);
        return 0;
    }

    printf("\nWriting main config...\n");
    if (write_config(main_config, main_entries, main_count, enable) != 0) {
        fprintf(stderr, "Error: Failed to write config\n");
        free(main_entries);
        return 1;
    }

    free(main_entries);

    printf("\nDone!\n");
    printf("To apply changes: sudo systemctl restart app_data_sec_loader\n");

    return 0;
}
