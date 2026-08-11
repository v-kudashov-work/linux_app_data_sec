// app_data_sec_loader.c - ОПТИМИЗИРОВАННАЯ ВЕРСИЯ (БЕЗ ПРОВЕРКИ НА ПОВТОРНЫЙ ЗАПУСК)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <dirent.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ (ОПТИМИЗИРОВАННЫЕ)
// ============================================================================

#define CONFIG_PATH "/etc/app_data_sec.conf"
#define MAX_LINE_LEN 1024
#define MAX_PATHS 5000
#define MAX_ALLOWED 20
#define MAX_PATH_LEN 256             // Вместо PATH_MAX (4096) -> 256
#define CHECK_INTERVAL 5
#define RETRY_INTERVAL 30
#define MAX_DEPTH_FOR_PATH 64
#define MAX_DEPTH_FOR_APP 8

// ============================================================================
// ОТЛАДКА
// ============================================================================
#define DEBUG_ENABLED 0

#ifdef DEBUG_ENABLED
#define DEBUG_PRINT(fmt, ...) \
do { \
    if (DEBUG_ENABLED) { \
        printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } \
} while (0)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

// ============================================================================
// ЛОГИРОВАНИЕ В SYSLOG
// ============================================================================

static void log_to_syslog(int priority, const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    openlog("app_data_sec_loader", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(priority, "%s", buffer);
    closelog();

    printf("%s\n", buffer);
    fflush(stdout);
}

#define SYSLOG_ERR(fmt, ...) log_to_syslog(LOG_ERR, "[ERROR] " fmt, ##__VA_ARGS__)
#define SYSLOG_WARN(fmt, ...) log_to_syslog(LOG_WARNING, "[WARNING] " fmt, ##__VA_ARGS__)
#define SYSLOG_INFO(fmt, ...) log_to_syslog(LOG_INFO, "[INFO] " fmt, ##__VA_ARGS__)

// ============================================================================
// ОПТИМИЗИРОВАННЫЕ СТРУКТУРЫ
// ============================================================================

struct protected_folder_config {
    __u64 folder_inode;
    __u32 allowed_program_count;
};

// Оптимизированная структура записи
struct protect_entry {
    char path[MAX_PATH_LEN];                          // 256 байт (было 4096)
    __u64 inode;                                      // 8 байт
    __u64 allowed_inodes[MAX_ALLOWED];                // 20 * 8 = 160 байт
    char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];    // 20 * 256 = 5120 байт
    int allowed_count;                                // 4 байта
    int is_active;                                    // 4 байта
    time_t last_check;                                // 8 байт
};
// Итого: ~5560 байт (вместо ~86192)
// 5000 записей = ~27.8 МБ (вместо ~430 МБ)

struct protect_template {
    char pattern[MAX_PATH_LEN];                       // 256 байт
    char subpath[MAX_PATH_LEN];                       // 256 байт
    __u64 allowed_inodes[MAX_ALLOWED];                // 160 байт
    char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];    // 5120 байт
    int allowed_count;                                // 4 байта
    int enabled;                                      // 4 байта
};
// Итого: ~5800 байт
// 5000 записей = ~29 МБ

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

static struct protect_entry entries[MAX_PATHS];
static struct protect_template templates[MAX_PATHS];
static int entry_count = 0;
static int template_count = 0;
static int config_enabled = 0;
static time_t config_mtime = 0;
static struct bpf_object *g_bpf_obj = NULL;

// ============================================================================
// БЕЗОПАСНОЕ КОПИРОВАНИЕ СТРОК
// ============================================================================

static void safe_strcpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) return;
    size_t src_len = strnlen(src, size - 1);
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
}

// ============================================================================
// ФУНКЦИИ РАБОТЫ С ФАЙЛОВОЙ СИСТЕМОЙ
// ============================================================================

static __u64 get_inode_from_path(const char *path) {
    if (!path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_ino;
}

static int path_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0);
}

// ============================================================================
// СКАНИРОВАНИЕ ДОМАШНИХ ДИРЕКТОРИЙ
// ============================================================================

static int scan_home_for_template(const char *subpath, char **found_paths, int max_paths) {
    struct passwd *pw;
    int idx = 0;

    if (!subpath || !found_paths || max_paths == 0) {
        return 0;
    }

    setpwent();
    while ((pw = getpwent()) != NULL && idx < max_paths) {
        if (!pw->pw_dir || pw->pw_dir[0] != '/') continue;
        if (strncmp(pw->pw_dir, "/home/", 6) != 0) continue;
        if (pw->pw_uid < 1000) continue;

        char expanded[PATH_MAX];
        int ret = snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
        if (ret < 0 || ret >= (int)sizeof(expanded)) continue;

        if (path_exists(expanded)) {
            found_paths[idx] = strdup(expanded);
            if (found_paths[idx]) idx++;
        }
    }
    endpwent();

    DIR *dir = opendir("/home/");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && idx < max_paths) {
            if (entry->d_name[0] == '.') continue;

            char expanded[PATH_MAX];
            int ret = snprintf(expanded, sizeof(expanded), "/home/%s%s", entry->d_name, subpath);
            if (ret < 0 || ret >= (int)sizeof(expanded)) continue;

            int already_added = 0;
            for (int i = 0; i < idx; i++) {
                if (found_paths[i] && strcmp(found_paths[i], expanded) == 0) {
                    already_added = 1;
                    break;
                }
            }

            if (!already_added && path_exists(expanded)) {
                found_paths[idx] = strdup(expanded);
                if (found_paths[idx]) idx++;
            }
        }
        closedir(dir);
    }

    return idx;
}

// ============================================================================
// ПАРСИНГ КОНФИГУРАЦИИ
// ============================================================================

static int parse_config(void) {
    DEBUG_PRINT("parse_config: start");

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        SYSLOG_WARN("Config file %s not found", CONFIG_PATH);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int line_num = 0;
    int new_entry_count = 0;
    int new_template_count = 0;
    int new_config_enabled = 0;

    memset(entries, 0, sizeof(entries));
    memset(templates, 0, sizeof(templates));

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        char *start = line;
        while (*start == ' ' || *start == '\t') start++;

        if (*start == '\0' || *start == '#') continue;

        char *end = start + strlen(start) - 1;
        while (end > start && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        if (strncmp(start, "enable", 6) == 0) {
            char *eq = strchr(start, '=');
            if (eq) {
                char *value = eq + 1;
                while (*value == ' ' || *value == '\t') value++;
                if (strcmp(value, "yes") == 0 || strcmp(value, "on") == 0 || strcmp(value, "1") == 0) {
                    new_config_enabled = 1;
                    SYSLOG_INFO("Config: enabled=yes");
                } else {
                    new_config_enabled = 0;
                    SYSLOG_INFO("Config: enabled=no");
                }
            }
            continue;
        }

        if (strncmp(start, "protect", 7) == 0) {
            char *ptr = start + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                SYSLOG_WARN("Config line %d: missing path after protect", line_num);
                continue;
            }

            char raw_path[MAX_PATH_LEN];
            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= sizeof(raw_path)) path_len = sizeof(raw_path) - 1;
            memcpy(raw_path, ptr, path_len);
            raw_path[path_len] = '\0';

            __u64 allowed_inodes[MAX_ALLOWED];
            char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];
            int allowed_count = 0;
            memset(allowed_inodes, 0, sizeof(allowed_inodes));
            memset(allowed_paths, 0, sizeof(allowed_paths));

            ptr = path_end;
            while (*ptr) {
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (*ptr == '\0') break;

                char *arg_end = ptr;
                while (*arg_end && *arg_end != ' ' && *arg_end != '\t') arg_end++;

                size_t arg_len = arg_end - ptr;
                if (arg_len > 0 && allowed_count < MAX_ALLOWED) {
                    char prog_path[PATH_MAX];
                    strncpy(prog_path, ptr, arg_len);
                    prog_path[arg_len] = '\0';

                    char real_allowed_path[PATH_MAX];
                    if (realpath(prog_path, real_allowed_path) != NULL) {
                        __u64 allowed_inode = get_inode_from_path(real_allowed_path);
                        if (allowed_inode != 0) {
                            allowed_inodes[allowed_count] = allowed_inode;
                            safe_strcpy(allowed_paths[allowed_count], real_allowed_path, MAX_PATH_LEN);
                            allowed_count++;
                            SYSLOG_INFO("  Allowed program: %s (inode: %lu)",
                                        real_allowed_path, (unsigned long)allowed_inode);
                        }
                    } else {
                        SYSLOG_WARN("  Allowed program '%s' not found", prog_path);
                    }
                }

                ptr = arg_end;
            }

            if (raw_path[0] == '~') {
                struct protect_template *tmpl = &templates[new_template_count];
                safe_strcpy(tmpl->pattern, raw_path, sizeof(tmpl->pattern));
                const char *subpath = raw_path + 1;
                safe_strcpy(tmpl->subpath, subpath, sizeof(tmpl->subpath));

                for (int i = 0; i < allowed_count && i < MAX_ALLOWED; i++) {
                    tmpl->allowed_inodes[i] = allowed_inodes[i];
                    safe_strcpy(tmpl->allowed_paths[i], allowed_paths[i], MAX_PATH_LEN);
                }
                tmpl->allowed_count = allowed_count;
                tmpl->enabled = 1;

                SYSLOG_INFO("Config: template ~%s (will scan all users)", tmpl->subpath);
                new_template_count++;

                char *found_paths[MAX_PATHS];
                int found_count = scan_home_for_template(tmpl->subpath, found_paths, MAX_PATHS);

                for (int i = 0; i < found_count && new_entry_count < MAX_PATHS; i++) {
                    struct protect_entry *entry = &entries[new_entry_count];
                    safe_strcpy(entry->path, found_paths[i], sizeof(entry->path));

                    entry->inode = get_inode_from_path(entry->path);
                    entry->is_active = (entry->inode != 0);
                    entry->allowed_count = 0;
                    entry->last_check = time(NULL);

                    for (int j = 0; j < tmpl->allowed_count && j < MAX_ALLOWED; j++) {
                        entry->allowed_inodes[j] = tmpl->allowed_inodes[j];
                        safe_strcpy(entry->allowed_paths[j], tmpl->allowed_paths[j], MAX_PATH_LEN);
                        entry->allowed_count++;
                    }

                    if (entry->inode != 0) {
                        SYSLOG_INFO("Config: protect %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
                    } else {
                        SYSLOG_WARN("Config: protect %s (NOT FOUND YET, will retry)", entry->path);
                    }

                    new_entry_count++;
                    free(found_paths[i]);
                }
            } else {
                struct protect_entry *entry = &entries[new_entry_count];
                safe_strcpy(entry->path, raw_path, sizeof(entry->path));

                entry->inode = get_inode_from_path(entry->path);
                entry->is_active = (entry->inode != 0);
                entry->allowed_count = 0;
                entry->last_check = time(NULL);

                for (int i = 0; i < allowed_count && i < MAX_ALLOWED; i++) {
                    entry->allowed_inodes[i] = allowed_inodes[i];
                    safe_strcpy(entry->allowed_paths[i], allowed_paths[i], MAX_PATH_LEN);
                    entry->allowed_count++;
                }

                if (entry->inode != 0) {
                    SYSLOG_INFO("Config: protect %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
                } else {
                    SYSLOG_WARN("Config: protect %s (NOT FOUND YET, will retry)", entry->path);
                }

                new_entry_count++;
            }
        }
    }

    fclose(fp);

    entry_count = new_entry_count;
    template_count = new_template_count;
    config_enabled = new_config_enabled;

    struct stat st;
    if (stat(CONFIG_PATH, &st) == 0) {
        config_mtime = st.st_mtime;
    }

    SYSLOG_INFO("Config: loaded %d entries, %d templates", entry_count, template_count);
    return 0;
}

// ============================================================================
// ЗАГРУЗКА В BPF
// ============================================================================

static int load_entries_to_bpf(struct bpf_object *obj) {
    struct bpf_map *map;
    int err;
    int fd;

    if (entry_count == 0) {
        SYSLOG_INFO("No entries to load");
        return 0;
    }

    map = bpf_object__find_map_by_name(obj, "folder_config_map");
    if (!map) {
        SYSLOG_ERR("Failed to find folder_config_map");
        return -1;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        SYSLOG_ERR("Failed to get map fd");
        return fd;
    }

    SYSLOG_INFO("Loading %d protected folders to BPF...", entry_count);

    for (int i = 0; i < entry_count && i < MAX_PATHS; i++) {
        if (entries[i].inode == 0) continue;

        struct protected_folder_config config = {
            .folder_inode = entries[i].inode,
            .allowed_program_count = entries[i].allowed_count,
        };

        err = bpf_map_update_elem(fd, &entries[i].inode, &config, BPF_ANY);
        if (err < 0) {
            SYSLOG_ERR("  Failed to update folder_config_map for inode %lu: %d",
                       (unsigned long)entries[i].inode, err);
        } else {
            SYSLOG_INFO("  [%d] Loaded folder: %s (inode: %lu, programs: %d)",
                        i, entries[i].path, (unsigned long)entries[i].inode,
                        config.allowed_program_count);
        }
    }

    map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
    if (!map) {
        SYSLOG_ERR("Failed to find folder_allowed_programs_map");
        return -1;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        SYSLOG_ERR("Failed to get map fd for folder_allowed_programs_map");
        return fd;
    }

    int total_programs = 0;
    for (int i = 0; i < entry_count && i < MAX_PATHS; i++) {
        if (entries[i].inode == 0) continue;

        for (int j = 0; j < entries[i].allowed_count && j < MAX_ALLOWED; j++) {
            __u64 key = (entries[i].inode << 32) | j;
            __u64 value = entries[i].allowed_inodes[j];

            err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
            if (err < 0) {
                SYSLOG_ERR("  Failed to update folder_allowed_programs_map for folder %lu, prog %d: %d",
                           (unsigned long)entries[i].inode, j, err);
            } else {
                SYSLOG_INFO("  [%lu] Program %d: %s (inode: %lu)",
                            (unsigned long)entries[i].inode, j,
                            entries[i].allowed_paths[j],
                            (unsigned long)entries[i].allowed_inodes[j]);
                total_programs++;
            }
        }
    }

    SYSLOG_INFO("Total loaded: %d folders, %d programs", entry_count, total_programs);
    return 0;
}

// ============================================================================
// УДАЛЕНИЕ ПАПКИ ИЗ BPF
// ============================================================================

static int remove_folder_from_bpf(struct bpf_object *obj, __u64 folder_inode) {
    if (folder_inode == 0) return -1;

    int err;
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(obj, "folder_config_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            err = bpf_map_delete_elem(fd, &folder_inode);
            if (err < 0 && err != -ENOENT) {
                SYSLOG_ERR("Failed to remove folder_config for inode %lu: %d",
                           (unsigned long)folder_inode, err);
            }
        }
    }

    map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            for (int i = 0; i < MAX_ALLOWED; i++) {
                __u64 key = (folder_inode << 32) | i;
                bpf_map_delete_elem(fd, &key);
            }
        }
    }

    return 0;
}

// ============================================================================
// ПЕРЕЗАГРУЗКА ВСЕХ ЗАПИСЕЙ
// ============================================================================

static int reload_all_entries(struct bpf_object *obj) {
    SYSLOG_INFO("Reloading all entries to BPF...");
    return load_entries_to_bpf(obj);
}

// ============================================================================
// ЗАГРУЗКА ОДНОЙ ЗАПИСИ
// ============================================================================

static int load_single_entry(struct bpf_object *obj, struct protect_entry *entry) {
    if (!entry || entry->inode == 0) return -1;

    struct protected_folder_config config = {
        .folder_inode = entry->inode,
        .allowed_program_count = entry->allowed_count,
    };

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_config_map");
    if (!map) return -1;

    int fd = bpf_map__fd(map);
    if (fd < 0) return fd;

    int err = bpf_map_update_elem(fd, &entry->inode, &config, BPF_ANY);
    if (err < 0) {
        SYSLOG_ERR("Failed to load entry %s: %d", entry->path, err);
        return err;
    }

    entry->is_active = 1;
    SYSLOG_INFO("  Loaded: %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
    return 0;
}

// ============================================================================
// ПРОВЕРКА НОВЫХ ПАПОК ПО ШАБЛОНАМ
// ============================================================================

static int scan_templates_and_load(struct bpf_object *obj) {
    int found_new = 0;

    for (int t = 0; t < template_count; t++) {
        if (!templates[t].enabled) continue;

        char *found_paths[MAX_PATHS];
        int found_count = scan_home_for_template(templates[t].subpath, found_paths, MAX_PATHS);

        for (int i = 0; i < found_count; i++) {
            if (!found_paths[i]) continue;

            int already_exists = 0;
            for (int j = 0; j < entry_count; j++) {
                if (strcmp(entries[j].path, found_paths[i]) == 0) {
                    already_exists = 1;
                    break;
                }
            }

            if (already_exists) {
                free(found_paths[i]);
                continue;
            }

            if (entry_count < MAX_PATHS) {
                struct protect_entry *entry = &entries[entry_count];
                safe_strcpy(entry->path, found_paths[i], sizeof(entry->path));

                entry->inode = get_inode_from_path(entry->path);
                entry->is_active = (entry->inode != 0);
                entry->last_check = time(NULL);
                entry->allowed_count = 0;

                for (int j = 0; j < templates[t].allowed_count && j < MAX_ALLOWED; j++) {
                    entry->allowed_inodes[j] = templates[t].allowed_inodes[j];
                    safe_strcpy(entry->allowed_paths[j], templates[t].allowed_paths[j], MAX_PATH_LEN);
                    entry->allowed_count++;
                }

                if (entry->inode != 0) {
                    SYSLOG_INFO("  New folder from template: %s (inode: %lu)",
                                entry->path, (unsigned long)entry->inode);
                    if (load_single_entry(obj, entry) == 0) {
                        found_new = 1;
                    }
                }

                entry_count++;
                free(found_paths[i]);
            } else {
                SYSLOG_WARN("Max entries reached, cannot add %s", found_paths[i]);
                free(found_paths[i]);
            }
        }
    }

    return found_new;
}

// ============================================================================
// ПРОВЕРКА ИЗМЕНЕНИЯ КОНФИГА
// ============================================================================

static int config_changed(void) {
    struct stat st;
    if (stat(CONFIG_PATH, &st) != 0) return 0;

    if (st.st_mtime != config_mtime) {
        config_mtime = st.st_mtime;
        return 1;
    }
    return 0;
}

// ============================================================================
// ФУНКЦИЯ ПОИСКА BPF ОБЪЕКТА
// ============================================================================

static const char* find_bpf_object(void) {
    static char path[PATH_MAX];
    struct stat st;

    const char *paths[] = {
        "/usr/local/lib/app_data_sec/app_data_sec.bpf.o",
        "./app_data_sec.bpf.o",
        "../app_data_sec.bpf.o",
        "/opt/app_data_sec/app_data_sec.bpf.o",
        "/usr/lib/app_data_sec/app_data_sec.bpf.o",
        "/usr/local/app_data_sec.bpf.o",
        NULL
    };

    for (int i = 0; paths[i] != NULL; i++) {
        if (stat(paths[i], &st) == 0 && S_ISREG(st.st_mode)) {
            strcpy(path, paths[i]);
            SYSLOG_INFO("Found BPF object: %s", path);
            return path;
        }
    }

    SYSLOG_ERR("BPF object file not found!");
    return NULL;
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -l, --log-level <0-2>  Set log level (0=off, 1=blocked only, 2=everything, default=1)\n");
    fprintf(stderr, "  -h, --help             Show this help\n");
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    struct bpf_map *map;
    int err = 0;
    int log_level = 1;
    const char *bpf_file = NULL;

    // Вывод информации о размере структур
    printf("sizeof(protect_entry) = %zu bytes\n", sizeof(struct protect_entry));
    printf("sizeof(protect_template) = %zu bytes\n", sizeof(struct protect_template));
    printf("entries array (%d): %zu KB\n", MAX_PATHS, (sizeof(entries) / 1024));
    printf("templates array (%d): %zu KB\n", MAX_PATHS, (sizeof(templates) / 1024));
    printf("Total: %zu KB (%.2f MB)\n",
           (sizeof(entries) + sizeof(templates)) / 1024,
           (double)(sizeof(entries) + sizeof(templates)) / (1024 * 1024));

    openlog("app_data_sec_loader", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    SYSLOG_INFO("APP DATA SEC LOADER STARTING (PID: %d)", getpid());

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 < argc) {
                log_level = atoi(argv[i + 1]);
                if (log_level < 0 || log_level > 2) {
                    SYSLOG_ERR("Invalid log_level: %d", log_level);
                    print_usage(argv[0]);
                    return 1;
                }
                i++;
            } else {
                SYSLOG_ERR("--log-level requires a value");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            SYSLOG_ERR("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    int requested_log_level = log_level;

    memset(entries, 0, sizeof(entries));
    memset(templates, 0, sizeof(templates));
    entry_count = 0;
    template_count = 0;
    config_enabled = 0;
    config_mtime = 0;

    bpf_file = find_bpf_object();
    if (!bpf_file) {
        SYSLOG_ERR("BPF object file not found!");
        closelog();
        return 1;
    }

    if (parse_config() != 0) {
        SYSLOG_ERR("Failed to parse config");
        closelog();
        return 1;
    }

    g_bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(g_bpf_obj)) {
        SYSLOG_ERR("Failed to open BPF object %s: %s", bpf_file, strerror(-libbpf_get_error(g_bpf_obj)));
        closelog();
        return 1;
    }

    err = bpf_object__load(g_bpf_obj);
    if (err) {
        SYSLOG_ERR("Failed to load BPF object: %d", err);
        goto cleanup;
    }

    if (config_enabled && entry_count > 0) {
        err = load_entries_to_bpf(g_bpf_obj);
        if (err) {
            SYSLOG_ERR("Failed to load entries: %d", err);
            goto cleanup;
        }
    } else {
        SYSLOG_INFO("No entries to load (config_enabled=%d, entry_count=%d)",
                    config_enabled, entry_count);
    }

    bpf_object__for_each_program(prog, g_bpf_obj) {
        const char *name = bpf_program__name(prog);
        if (strncmp(name, "block_", 6) != 0) continue;

        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (link) {
            SYSLOG_INFO("Attached: %s", name);
        } else {
            SYSLOG_ERR("Failed to attach: %s", name);
        }
    }

    map = bpf_object__find_map_by_name(g_bpf_obj, "log_level_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 key = 0;
            __u32 log_level_val = requested_log_level;
            bpf_map_update_elem(fd, &key, &log_level_val, BPF_ANY);
        }
    }

    SYSLOG_INFO("eBPF LSM programs attached. %d entries loaded, %d templates",
                entry_count, template_count);
    SYSLOG_INFO("Log level: %d (0=off, 1=blocked only, 2=everything)", requested_log_level);
    SYSLOG_INFO("Auto-reload enabled: config check every %d seconds, new folders every %d seconds",
                CHECK_INTERVAL, RETRY_INTERVAL);
    SYSLOG_INFO("Config file: %s", CONFIG_PATH);

    time_t last_folder_check = time(NULL);

    while (1) {
        sleep(CHECK_INTERVAL);
        time_t now = time(NULL);

        if (config_changed()) {
            SYSLOG_INFO("Config changed! Reloading...");

            __u64 old_inodes[MAX_PATHS];
            int old_count = 0;
            for (int i = 0; i < entry_count; i++) {
                if (entries[i].inode != 0) {
                    old_inodes[old_count++] = entries[i].inode;
                }
            }

            memset(entries, 0, sizeof(entries));
            memset(templates, 0, sizeof(templates));
            entry_count = 0;
            template_count = 0;
            config_enabled = 0;
            config_mtime = 0;

            if (parse_config() != 0) {
                SYSLOG_ERR("Failed to parse config after change");
                continue;
            }

            if (!config_enabled) {
                SYSLOG_INFO("Config: module disabled");
                for (int i = 0; i < old_count; i++) {
                    remove_folder_from_bpf(g_bpf_obj, old_inodes[i]);
                }
                continue;
            }

            if (entry_count == 0) {
                SYSLOG_WARN("No entries in config, waiting...");
                continue;
            }

            for (int i = 0; i < old_count; i++) {
                int found = 0;
                for (int j = 0; j < entry_count; j++) {
                    if (entries[j].inode == old_inodes[i]) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    SYSLOG_INFO("Removing old folder: %lu", (unsigned long)old_inodes[i]);
                    remove_folder_from_bpf(g_bpf_obj, old_inodes[i]);
                }
            }

            reload_all_entries(g_bpf_obj);
            last_folder_check = now;
        }

        if (now - last_folder_check >= RETRY_INTERVAL) {
            int changed = 0;

            for (int i = 0; i < entry_count; i++) {
                if (entries[i].path[0] == '\0') continue;

                __u64 current_inode = get_inode_from_path(entries[i].path);

                if (current_inode == 0) {
                    if (entries[i].inode != 0 && entries[i].is_active) {
                        SYSLOG_INFO("Folder removed: %s", entries[i].path);
                        remove_folder_from_bpf(g_bpf_obj, entries[i].inode);
                        entries[i].inode = 0;
                        entries[i].is_active = 0;
                        changed = 1;
                    }
                } else if (entries[i].inode == 0) {
                    entries[i].inode = current_inode;
                    entries[i].is_active = 1;
                    SYSLOG_INFO("New folder found: %s (inode: %lu)",
                                entries[i].path, (unsigned long)current_inode);
                    load_single_entry(g_bpf_obj, &entries[i]);
                    changed = 1;
                } else if (entries[i].inode != current_inode) {
                    SYSLOG_INFO("Folder recreated: %s (old: %lu, new: %lu)",
                                entries[i].path,
                                (unsigned long)entries[i].inode,
                                (unsigned long)current_inode);
                    remove_folder_from_bpf(g_bpf_obj, entries[i].inode);
                    entries[i].inode = current_inode;
                    entries[i].is_active = 1;
                    load_single_entry(g_bpf_obj, &entries[i]);
                    changed = 1;
                }
            }

            if (scan_templates_and_load(g_bpf_obj)) {
                changed = 1;
            }

            if (changed) {
                SYSLOG_INFO("Changes detected, reloading all entries...");
                reload_all_entries(g_bpf_obj);
            }

            last_folder_check = now;
        }
    }

    cleanup:
    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
    }
    SYSLOG_INFO("APP DATA SEC LOADER EXITING");
    closelog();
    return err;
}
