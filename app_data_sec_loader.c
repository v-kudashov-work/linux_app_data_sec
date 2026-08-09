// app_data_sec_loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>      // Добавлено для strcmp, strncpy, memcpy
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

#define CONFIG_PATH "/etc/app_data_sec.conf"
#define MAX_LINE_LEN 1024
#define MAX_PATHS 5000
#define MAX_ALLOWED 10
#define CHECK_INTERVAL 2          // Проверка конфига каждые 2 секунды
#define RETRY_INTERVAL 30         // Проверка новых папок каждые 30 секунд

// ============================================================================
// ОТЛАДКА - включить/выключить
// ============================================================================
#define DEBUG_ENABLED 1   // 1 - включить отладку, 0 - выключить

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

struct protect_entry {
    char path[PATH_MAX];
    __u64 inode;
    __u64 allowed_inodes[MAX_ALLOWED];
    int allowed_count;
    int is_expanded;
    int is_active;
    time_t last_check;
};

struct protect_entry entries[MAX_PATHS];
int entry_count = 0;
int config_enabled = 0;
time_t config_mtime = 0;

struct bpf_object *g_bpf_obj = NULL;

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
// ФУНКЦИИ РАБОТЫ С КОНФИГУРАЦИЕЙ
// ============================================================================

static __u64 get_inode_from_path(const char *path) {
    if (!path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_ino;
}

// Безопасное разворачивание ~ только для /home/
// Функция для поиска всех пользователей и разворачивания ~
static int expand_for_all_users(const char *pattern, char **expanded_paths, int *count) {
    struct passwd *pw;
    int idx = 0;

    if (!pattern || !expanded_paths || !count) {
        return -1;
    }

    // Если путь не начинается с ~, добавляем как есть
    if (pattern[0] != '~') {
        expanded_paths[idx] = strdup(pattern);
        if (expanded_paths[idx]) {
            idx++;
        }
        *count = idx;
        return 0;
    }

    const char *subpath = pattern + 1;  // часть после ~

    // Перебираем всех пользователей
    setpwent();
    while ((pw = getpwent()) != NULL && idx < MAX_PATHS) {
        if (!pw->pw_dir || pw->pw_dir[0] != '/') {
            continue;
        }

        // Проверяем, что домашняя директория начинается с /home/
        if (strncmp(pw->pw_dir, "/home/", 6) != 0) {
            continue;
        }

        // Проверяем, что это обычный пользователь (UID >= 1000)
        if (pw->pw_uid < 1000) {
            continue;
        }

        char expanded[PATH_MAX];
        int ret = snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
        if (ret < 0 || ret >= (int)sizeof(expanded)) {
            continue;
        }

        // Проверяем, существует ли папка
        struct stat st;
        if (stat(expanded, &st) == 0) {
            expanded_paths[idx] = strdup(expanded);
            if (expanded_paths[idx]) {
                idx++;
            }
        }
    }
    endpwent();

    // Дополнительно сканируем /home/ на случай удалённых пользователей
    DIR *dir = opendir("/home/");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && idx < MAX_PATHS) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (entry->d_name[0] == '.') {
                continue;
            }

            char user_home[PATH_MAX];
            int ret = snprintf(user_home, sizeof(user_home), "/home/%s", entry->d_name);
            if (ret < 0 || ret >= (int)sizeof(user_home)) {
                continue;
            }

            struct stat st;
            if (stat(user_home, &st) != 0 || !S_ISDIR(st.st_mode)) {
                continue;
            }

            char expanded[PATH_MAX];
            ret = snprintf(expanded, sizeof(expanded), "/home/%s%s", entry->d_name, subpath);
            if (ret < 0 || ret >= (int)sizeof(expanded)) {
                continue;
            }

            // Проверяем, не добавлена ли уже эта папка
            int already_added = 0;
            for (int i = 0; i < idx; i++) {
                if (expanded_paths[i] && strcmp(expanded_paths[i], expanded) == 0) {
                    already_added = 1;
                    break;
                }
            }

            if (!already_added && stat(expanded, &st) == 0) {
                expanded_paths[idx] = strdup(expanded);
                if (expanded_paths[idx]) {
                    idx++;
                }
            }
        }
        closedir(dir);
    }

    *count = idx;
    return 0;
}

// Парсинг конфигурации
static int parse_config(void) {
    DEBUG_PRINT("parse_config: start");

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Config file %s not found\n", CONFIG_PATH);
        return -1;
    }

    DEBUG_PRINT("parse_config: file opened");

    char line[MAX_LINE_LEN];
    int line_num = 0;
    int new_entry_count = 0;
    int new_config_enabled = 0;

    memset(entries, 0, sizeof(entries));
    entry_count = 0;

    DEBUG_PRINT("parse_config: reading lines");

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
                    printf("Config: enabled=yes\n");
                } else {
                    new_config_enabled = 0;
                    printf("Config: enabled=no\n");
                }
            }
            continue;
        }

        if (strncmp(start, "protect", 7) == 0) {
            DEBUG_PRINT("parse_config: found protect line %d", line_num);

            char *ptr = start + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                fprintf(stderr, "Config line %d: missing path after protect\n", line_num);
                continue;
            }

            // Извлекаем путь до первого пробела
            char raw_path[PATH_MAX];
            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= sizeof(raw_path)) path_len = sizeof(raw_path) - 1;
            memcpy(raw_path, ptr, path_len);
            raw_path[path_len] = '\0';

            DEBUG_PRINT("parse_config: raw_path = %s", raw_path);

            // Извлекаем разрешенные программы
            char *allowed[MAX_ALLOWED];
            int allowed_count = 0;
            memset(allowed, 0, sizeof(allowed));

            ptr = path_end;
            while (*ptr) {
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (*ptr == '\0') break;

                char *arg_end = ptr;
                while (*arg_end && *arg_end != ' ' && *arg_end != '\t') arg_end++;

                size_t arg_len = arg_end - ptr;
                if (arg_len > 0 && allowed_count < MAX_ALLOWED) {
                    allowed[allowed_count] = malloc(arg_len + 1);
                    if (allowed[allowed_count]) {
                        strncpy(allowed[allowed_count], ptr, arg_len);
                        allowed[allowed_count][arg_len] = '\0';
                        allowed_count++;
                    }
                }

                ptr = arg_end;
            }

            // Разворачиваем ~ для всех пользователей
            char *expanded_paths[MAX_PATHS];
            int expanded_count = 0;
            memset(expanded_paths, 0, sizeof(expanded_paths));

            if (raw_path[0] == '~') {
                expand_for_all_users(raw_path, expanded_paths, &expanded_count);
            } else {
                expanded_paths[0] = strdup(raw_path);
                expanded_count = 1;
            }

            if (expanded_count == 0) {
                printf("Config: protect %s (NO MATCHING FOLDERS FOUND)\n", raw_path);
                for (int j = 0; j < allowed_count; j++) {
                    free(allowed[j]);
                }
                continue;
            }

            for (int i = 0; i < expanded_count && new_entry_count < MAX_PATHS; i++) {
                if (!expanded_paths[i]) {
                    continue;
                }

                struct protect_entry *entry = &entries[new_entry_count];
                safe_strcpy(entry->path, expanded_paths[i], sizeof(entry->path));

                struct stat st;
                int exists = (stat(entry->path, &st) == 0);
                entry->inode = exists ? st.st_ino : 0;
                entry->is_active = exists;
                entry->allowed_count = 0;
                entry->last_check = time(NULL);

                // Добавляем разрешенные программы
                for (int j = 0; j < allowed_count && j < MAX_ALLOWED; j++) {
                    if (!allowed[j]) {
                        continue;
                    }

                    char real_allowed_path[PATH_MAX];
                    if (realpath(allowed[j], real_allowed_path) == NULL) {
                        fprintf(stderr, "Warning: Allowed program '%s' does not exist\n", allowed[j]);
                        continue;
                    }
                    __u64 allowed_inode = get_inode_from_path(real_allowed_path);
                    if (allowed_inode != 0) {
                        entry->allowed_inodes[entry->allowed_count] = allowed_inode;
                        entry->allowed_count++;
                        printf("Config: protect %s allowed: %s (inode: %lu)\n",
                               entry->path, real_allowed_path, (unsigned long)allowed_inode);
                    }
                }

                if (exists) {
                    printf("Config: protect %s (inode: %lu)\n", entry->path, (unsigned long)entry->inode);
                } else {
                    printf("Config: protect %s (NOT FOUND YET, will retry)\n", entry->path);
                }

                new_entry_count++;
                free(expanded_paths[i]);
                expanded_paths[i] = NULL;
            }

            for (int j = 0; j < allowed_count; j++) {
                free(allowed[j]);
                allowed[j] = NULL;
            }
        }
    }

    fclose(fp);

    entry_count = new_entry_count;
    config_enabled = new_config_enabled;

    struct stat st;
    if (stat(CONFIG_PATH, &st) == 0) {
        config_mtime = st.st_mtime;
    }

    printf("Config: loaded %d entries\n", entry_count);
    DEBUG_PRINT("parse_config: done, entry_count = %d", entry_count);
    return 0;
}

// ============================================================================
// ЗАГРУЗКА В BPF
// ============================================================================

static int remove_entry_from_bpf(struct bpf_object *obj, __u64 inode) {
    if (inode == 0) return -1;

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        fprintf(stderr, "Failed to find target_inode_map\n");
        return -1;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        return fd;
    }

    int err = bpf_map_delete_elem(fd, &inode);
    if (err < 0 && err != -ENOENT) {
        fprintf(stderr, "Failed to remove inode %lu from BPF: %d\n", (unsigned long)inode, err);
        return err;
    }

    return 0;
}

static int load_entry_to_bpf(struct bpf_object *obj, struct protect_entry *entry, int index) {
    if (!entry || entry->inode == 0) return -1;

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        fprintf(stderr, "Failed to find target_inode_map\n");
        return -1;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        return fd;
    }

    __u8 value = 1;
    int err = bpf_map_update_elem(fd, &entry->inode, &value, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "Failed to load entry %d (inode: %lu): %d\n",
                index, (unsigned long)entry->inode, err);
        return err;
    }

    entry->is_active = 1;
    printf("  [%d] Loaded: %s (inode: %lu)\n", index, entry->path, (unsigned long)entry->inode);
    return 0;
}

static int reload_all_entries(struct bpf_object *obj) {
    struct bpf_map *map;
    int fd;
    int err;
    int loaded = 0;
    int skipped = 0;
    int updated = 0;
    int removed = 0;

    printf("Reloading all entries to BPF...\n");

    map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        fprintf(stderr, "Failed to find target_inode_map\n");
        return -1;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        return fd;
    }

    for (int i = 0; i < entry_count; i++) {
        if (entries[i].path[0] == '\0') continue;

        __u64 current_inode = get_inode_from_path(entries[i].path);

        if (current_inode == 0) {
            if (entries[i].inode != 0 && entries[i].is_active) {
                printf("  [%d] Folder removed: %s (old inode: %lu)\n",
                       i, entries[i].path, (unsigned long)entries[i].inode);
                remove_entry_from_bpf(obj, entries[i].inode);
                entries[i].inode = 0;
                entries[i].is_active = 0;
                removed++;
            }
            skipped++;
            continue;
        }

        if (entries[i].inode == 0) {
            entries[i].inode = current_inode;
            printf("  [%d] New folder found: %s (inode: %lu)\n",
                   i, entries[i].path, (unsigned long)current_inode);
            updated++;
        } else if (entries[i].inode != current_inode) {
            printf("  [%d] Folder recreated: %s (old inode: %lu, new inode: %lu)\n",
                   i, entries[i].path, (unsigned long)entries[i].inode, (unsigned long)current_inode);
            entries[i].inode = current_inode;
            updated++;
        }

        __u8 value = 1;
        err = bpf_map_update_elem(fd, &entries[i].inode, &value, BPF_ANY);
        if (err < 0) {
            fprintf(stderr, "Failed to update entry %d: %d\n", i, err);
        } else {
            entries[i].is_active = 1;
            loaded++;
        }
    }

    // Обновляем разрешенные программы
    __u64 all_allowed[MAX_ALLOWED];
    int all_allowed_count = 0;
    memset(all_allowed, 0, sizeof(all_allowed));

    for (int i = 0; i < entry_count; i++) {
        for (int j = 0; j < entries[i].allowed_count && j < MAX_ALLOWED; j++) {
            __u64 inode = entries[i].allowed_inodes[j];

            int already_added = 0;
            for (int k = 0; k < all_allowed_count; k++) {
                if (all_allowed[k] == inode) {
                    already_added = 1;
                    break;
                }
            }

            if (!already_added && all_allowed_count < MAX_ALLOWED) {
                all_allowed[all_allowed_count++] = inode;
            }
        }
    }

    map = bpf_object__find_map_by_name(obj, "allowed_inode_map");
    if (map) {
        fd = bpf_map__fd(map);
        if (fd >= 0) {
            for (int i = 0; i < all_allowed_count && i < MAX_ALLOWED; i++) {
                __u32 key = i;
                bpf_map_update_elem(fd, &key, &all_allowed[i], BPF_ANY);
            }
        }
    }

    map = bpf_object__find_map_by_name(obj, "allowed_count_map");
    if (map) {
        fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 key = 0;
            __u32 count = all_allowed_count;
            bpf_map_update_elem(fd, &key, &count, BPF_ANY);
        }
    }

    printf("Reloaded: %d entries loaded, %d skipped, %d updated, %d removed\n",
           loaded, skipped, updated, removed);
    return 0;
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
    int err;
    int log_level = 1;
    const char *bpf_file = "app_data_sec.bpf.o";

    DEBUG_PRINT("main: start");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 < argc) {
                log_level = atoi(argv[i + 1]);
                if (log_level < 0 || log_level > 2) {
                    fprintf(stderr, "Error: log_level must be 0, 1, or 2\n");
                    print_usage(argv[0]);
                    return 1;
                }
                i++;
            } else {
                fprintf(stderr, "Error: --log-level requires a value\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    int requested_log_level = log_level;

    DEBUG_PRINT("main: before memset");

    memset(entries, 0, sizeof(entries));
    entry_count = 0;
    config_enabled = 0;
    config_mtime = 0;

    DEBUG_PRINT("main: before parse_config");

    if (parse_config() != 0) {
        fprintf(stderr, "Failed to parse config\n");
        return 1;
    }

    DEBUG_PRINT("main: after parse_config, enabled=%d, count=%d", config_enabled, entry_count);

    if (!config_enabled) {
        printf("Config: module disabled, exiting\n");
        return 0;
    }

    if (entry_count == 0) {
        printf("No valid protect entries found, exiting\n");
        return 0;
    }

    DEBUG_PRINT("main: before bpf_object__open_file");

    g_bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(g_bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object %s\n", bpf_file);
        return 1;
    }

    DEBUG_PRINT("main: before bpf_object__load");

    err = bpf_object__load(g_bpf_obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    DEBUG_PRINT("main: before reload_all_entries");

    err = reload_all_entries(g_bpf_obj);
    if (err) {
        goto cleanup;
    }

    DEBUG_PRINT("main: before log_level_map");

    map = bpf_object__find_map_by_name(g_bpf_obj, "log_level_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 key = 0;
            __u32 log_level_val = requested_log_level;
            bpf_map_update_elem(fd, &key, &log_level_val, BPF_ANY);
        }
    }

    DEBUG_PRINT("main: before attaching programs");

    bpf_object__for_each_program(prog, g_bpf_obj) {
        const char *name = bpf_program__name(prog);

        if (strncmp(name, "block_", 6) != 0) {
            continue;
        }

        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (link) {
            printf("Attached: %s\n", name);
        } else {
            fprintf(stderr, "Failed to attach: %s\n", name);
        }
    }

    printf("✅ eBPF LSM programs attached. %d entries loaded\n", entry_count);
    printf("📁 GETATTR: folder VISIBLE, contents PROTECTED\n");
    printf("🔒 ALL other operations: folder AND contents BLOCKED\n");
    printf("Log level: %d (0=off, 1=blocked only, 2=everything)\n", requested_log_level);
    printf("\n🔄 Auto-reload enabled:\n");
    printf("   Config check: every %d seconds\n", CHECK_INTERVAL);
    printf("   New folders check: every %d seconds\n", RETRY_INTERVAL);
    printf("   Config file: %s\n", CONFIG_PATH);
    printf("Press Ctrl-C to stop...\n\n");

    time_t last_folder_check = time(NULL);

    while (1) {
        sleep(CHECK_INTERVAL);
        time_t now = time(NULL);

        // === Проверка изменения конфига ===
        if (config_changed()) {
            printf("\n=== Config changed! Reloading ===\n");

            // Сохраняем старые inode для удаления
            __u64 old_inodes[MAX_PATHS];
            int old_inodes_count = 0;
            for (int i = 0; i < entry_count; i++) {
                if (entries[i].inode != 0 && entries[i].is_active) {
                    old_inodes[old_inodes_count++] = entries[i].inode;
                }
            }

            // Перезагружаем конфиг
            memset(entries, 0, sizeof(entries));
            entry_count = 0;
            config_enabled = 0;
            config_mtime = 0;

            if (parse_config() != 0) {
                fprintf(stderr, "Failed to parse config after change\n");
                continue;
            }

            if (!config_enabled) {
                printf("Config: module disabled\n");
                break;
            }

            // Удаляем старые записи из BPF
            for (int i = 0; i < old_inodes_count; i++) {
                if (old_inodes[i] != 0) {
                    int found = 0;
                    for (int j = 0; j < entry_count; j++) {
                        if (entries[j].inode == old_inodes[i]) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        printf("  Removing old inode: %lu\n", (unsigned long)old_inodes[i]);
                        remove_entry_from_bpf(g_bpf_obj, old_inodes[i]);
                    }
                }
            }

            reload_all_entries(g_bpf_obj);
            last_folder_check = time(NULL);  // Сбрасываем таймер проверки папок
        }

        // === Проверка новых папок ===
        if (now - last_folder_check >= RETRY_INTERVAL) {
            DEBUG_PRINT("checking for new folders...");

            int found_new = 0;

            // Проверяем новые папки (inode == 0)
            for (int i = 0; i < entry_count; i++) {
                if (entries[i].path[0] == '\0') continue;
                if (entries[i].is_active && entries[i].inode != 0) continue;

                __u64 current_inode = get_inode_from_path(entries[i].path);
                if (current_inode == 0) continue;

                entries[i].inode = current_inode;
                entries[i].is_active = 1;
                entries[i].last_check = time(NULL);

                printf("  New folder found: %s (inode: %lu)\n",
                       entries[i].path, (unsigned long)current_inode);

                if (load_entry_to_bpf(g_bpf_obj, &entries[i], i) == 0) {
                    found_new = 1;
                }
            }

            // Проверяем пересозданные папки (изменился inode)
            int found_recreated = 0;
            for (int i = 0; i < entry_count; i++) {
                if (entries[i].path[0] == '\0') continue;
                if (!entries[i].is_active || entries[i].inode == 0) continue;

                __u64 current_inode = get_inode_from_path(entries[i].path);
                if (current_inode == 0) {
                    printf("  Folder removed from filesystem: %s\n", entries[i].path);
                    remove_entry_from_bpf(g_bpf_obj, entries[i].inode);
                    entries[i].inode = 0;
                    entries[i].is_active = 0;
                    found_recreated = 1;
                } else if (entries[i].inode != current_inode) {
                    printf("  Folder recreated: %s (old inode: %lu, new inode: %lu)\n",
                           entries[i].path, (unsigned long)entries[i].inode, (unsigned long)current_inode);
                    remove_entry_from_bpf(g_bpf_obj, entries[i].inode);
                    entries[i].inode = current_inode;
                    entries[i].is_active = 1;
                    load_entry_to_bpf(g_bpf_obj, &entries[i], i);
                    found_recreated = 1;
                }
            }

            if (found_new || found_recreated) {
                reload_all_entries(g_bpf_obj);
            }

            last_folder_check = now;
        }
    }

    cleanup:
    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
    }
    printf("Exit\n");
    return err;
}
