// app_data_sec_loader.c
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

#define CONFIG_PATH "/etc/app_data_sec.conf"
#define MAX_LINE_LEN 1024
#define MAX_PATHS 5000
#define MAX_ALLOWED 10
#define CHECK_INTERVAL 5
#define RETRY_INTERVAL 30

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

struct protect_entry {
    char path[PATH_MAX];
    __u64 inode;
    __u64 allowed_inodes[MAX_ALLOWED];
    char allowed_paths[MAX_ALLOWED][PATH_MAX];
    int allowed_count;
    int is_expanded;
    int is_active;
    time_t last_check;
};

// Структура для хранения шаблона с ~
struct protect_template {
    char pattern[PATH_MAX];
    char subpath[PATH_MAX];
    __u64 allowed_inodes[MAX_ALLOWED];
    char allowed_paths[MAX_ALLOWED][PATH_MAX];
    int allowed_count;
    int enabled;
};

struct protect_entry entries[MAX_PATHS];
struct protect_template templates[MAX_PATHS];
int entry_count = 0;
int template_count = 0;
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

// Проверка, существует ли путь
static int path_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0);
}

// Сканирование всех домашних директорий и поиск папок по шаблону
static int scan_home_for_template(const char *subpath, char **found_paths, int max_paths) {
    struct passwd *pw;
    int idx = 0;

    if (!subpath || !found_paths || max_paths == 0) {
        return 0;
    }

    setpwent();
    while ((pw = getpwent()) != NULL && idx < max_paths) {
        if (!pw->pw_dir || pw->pw_dir[0] != '/') {
            continue;
        }

        if (strncmp(pw->pw_dir, "/home/", 6) != 0) {
            continue;
        }

        if (pw->pw_uid < 1000) {
            continue;
        }

        char expanded[PATH_MAX];
        int ret = snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
        if (ret < 0 || ret >= (int)sizeof(expanded)) {
            continue;
        }

        if (path_exists(expanded)) {
            found_paths[idx] = strdup(expanded);
            if (found_paths[idx]) {
                idx++;
            }
        }
    }
    endpwent();

    DIR *dir = opendir("/home/");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL && idx < max_paths) {
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

            int already_added = 0;
            for (int i = 0; i < idx; i++) {
                if (found_paths[i] && strcmp(found_paths[i], expanded) == 0) {
                    already_added = 1;
                    break;
                }
            }

            if (!already_added && path_exists(expanded)) {
                found_paths[idx] = strdup(expanded);
                if (found_paths[idx]) {
                    idx++;
                }
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

    DEBUG_PRINT("parse_config: file opened");

    char line[MAX_LINE_LEN];
    int line_num = 0;
    int new_entry_count = 0;
    int new_template_count = 0;
    int new_config_enabled = 0;

    memset(entries, 0, sizeof(entries));
    memset(templates, 0, sizeof(templates));
    entry_count = 0;
    template_count = 0;

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
                    SYSLOG_INFO("Config: enabled=yes");
                } else {
                    new_config_enabled = 0;
                    SYSLOG_INFO("Config: enabled=no");
                }
            }
            continue;
        }

        if (strncmp(start, "protect", 7) == 0) {
            DEBUG_PRINT("parse_config: found protect line %d", line_num);

            char *ptr = start + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                SYSLOG_WARN("Config line %d: missing path after protect", line_num);
                continue;
            }

            char raw_path[PATH_MAX];
            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= sizeof(raw_path)) path_len = sizeof(raw_path) - 1;
            memcpy(raw_path, ptr, path_len);
            raw_path[path_len] = '\0';

            DEBUG_PRINT("parse_config: raw_path = %s", raw_path);

            __u64 allowed_inodes[MAX_ALLOWED];
            char allowed_paths[MAX_ALLOWED][PATH_MAX];
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
                            strcpy(allowed_paths[allowed_count], real_allowed_path);
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
                    strcpy(tmpl->allowed_paths[i], allowed_paths[i]);
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
                        strcpy(entry->allowed_paths[j], tmpl->allowed_paths[j]);
                        entry->allowed_count++;
                    }

                    if (entry->inode != 0) {
                        SYSLOG_INFO("Config: protect %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
                        if (entry->allowed_count > 0) {
                            char prog_list[2048] = "";
                            for (int j = 0; j < entry->allowed_count && j < MAX_ALLOWED; j++) {
                                char temp[512];
                                if (j == 0) {
                                    snprintf(temp, sizeof(temp), "%s (inode: %lu)",
                                             entry->allowed_paths[j], (unsigned long)entry->allowed_inodes[j]);
                                } else {
                                    snprintf(temp, sizeof(temp), ", %s (inode: %lu)",
                                             entry->allowed_paths[j], (unsigned long)entry->allowed_inodes[j]);
                                }
                                strncat(prog_list, temp, sizeof(prog_list) - strlen(prog_list) - 1);
                            }
                            SYSLOG_INFO("  Allowed programs: %s", prog_list);
                        } else {
                            SYSLOG_INFO("  Allowed programs: none (only root)");
                        }
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
                    strcpy(entry->allowed_paths[i], allowed_paths[i]);
                    entry->allowed_count++;
                }

                if (entry->inode != 0) {
                    SYSLOG_INFO("Config: protect %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
                    if (entry->allowed_count > 0) {
                        char prog_list[2048] = "";
                        for (int j = 0; j < entry->allowed_count && j < MAX_ALLOWED; j++) {
                            char temp[512];
                            if (j == 0) {
                                snprintf(temp, sizeof(temp), "%s (inode: %lu)",
                                         entry->allowed_paths[j], (unsigned long)entry->allowed_inodes[j]);
                            } else {
                                snprintf(temp, sizeof(temp), ", %s (inode: %lu)",
                                         entry->allowed_paths[j], (unsigned long)entry->allowed_inodes[j]);
                            }
                            strncat(prog_list, temp, sizeof(prog_list) - strlen(prog_list) - 1);
                        }
                        SYSLOG_INFO("  Allowed programs: %s", prog_list);
                    } else {
                        SYSLOG_INFO("  Allowed programs: none (only root)");
                    }
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
    DEBUG_PRINT("parse_config: done, entry_count = %d, template_count = %d", entry_count, template_count);
    return 0;
}

// ============================================================================
// УДАЛЕНИЕ ИЗ BPF
// ============================================================================

static int remove_entry_from_bpf(struct bpf_object *obj, __u64 inode) {
    if (inode == 0) return -1;

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        SYSLOG_ERR("Failed to find target_inode_map");
        return -1;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        SYSLOG_ERR("Failed to get map fd");
        return fd;
    }

    int err = bpf_map_delete_elem(fd, &inode);
    if (err < 0 && err != -ENOENT) {
        SYSLOG_ERR("Failed to remove inode %lu from BPF: %d", (unsigned long)inode, err);
        return err;
    }

    return 0;
}

// ============================================================================
// ЗАГРУЗКА ОДНОЙ ЗАПИСИ В BPF
// ============================================================================

static int load_entry_to_bpf(struct bpf_object *obj, struct protect_entry *entry, int index) {
    if (!entry || entry->inode == 0) return -1;

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        SYSLOG_ERR("Failed to find target_inode_map");
        return -1;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        SYSLOG_ERR("Failed to get map fd");
        return fd;
    }

    __u8 value = 1;
    int err = bpf_map_update_elem(fd, &entry->inode, &value, BPF_ANY);
    if (err < 0) {
        SYSLOG_ERR("Failed to load entry %d (inode: %lu): %d",
                   index, (unsigned long)entry->inode, err);
        return err;
    }

    entry->is_active = 1;
    SYSLOG_INFO("  [%d] Loaded: %s (inode: %lu)", index, entry->path, (unsigned long)entry->inode);
    return 0;
}

// ============================================================================
// ПЕРЕЗАГРУЗКА ВСЕХ ЗАПИСЕЙ
// ============================================================================

static int reload_all_entries(struct bpf_object *obj) {
    struct bpf_map *map;
    int fd;
    int err;
    int loaded = 0;
    int skipped = 0;
    int updated = 0;
    int removed = 0;

    SYSLOG_INFO("Reloading all entries to BPF...");

    map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        SYSLOG_ERR("Failed to find target_inode_map");
        return -1;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        SYSLOG_ERR("Failed to get map fd");
        return fd;
    }

    for (int i = 0; i < entry_count; i++) {
        if (entries[i].path[0] == '\0') continue;

        __u64 current_inode = get_inode_from_path(entries[i].path);

        if (current_inode == 0) {
            if (entries[i].inode != 0 && entries[i].is_active) {
                SYSLOG_INFO("  [%d] Folder removed: %s (old inode: %lu)",
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
            SYSLOG_INFO("  [%d] New folder found: %s (inode: %lu)",
                        i, entries[i].path, (unsigned long)current_inode);
            updated++;
        } else if (entries[i].inode != current_inode) {
            SYSLOG_INFO("  [%d] Folder recreated: %s (old inode: %lu, new inode: %lu)",
                        i, entries[i].path, (unsigned long)entries[i].inode, (unsigned long)current_inode);
            entries[i].inode = current_inode;
            updated++;
        }

        __u8 value = 1;
        err = bpf_map_update_elem(fd, &entries[i].inode, &value, BPF_ANY);
        if (err < 0) {
            SYSLOG_ERR("Failed to update entry %d: %d", i, err);
        } else {
            entries[i].is_active = 1;
            loaded++;
        }
    }

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

    SYSLOG_INFO("Reloaded: %d entries loaded, %d skipped, %d updated, %d removed",
                loaded, skipped, updated, removed);
    return 0;
}

// ============================================================================
// ПРОВЕРКА НОВЫХ ПАПОК ПО ШАБЛОНАМ
// ============================================================================

static int scan_templates_and_load(struct bpf_object *obj) {
    int found_new = 0;
    int total_found = 0;

    for (int t = 0; t < template_count; t++) {
        if (!templates[t].enabled) continue;

        DEBUG_PRINT("scanning template: ~%s", templates[t].subpath);

        char *found_paths[MAX_PATHS];
        int found_count = scan_home_for_template(templates[t].subpath, found_paths, MAX_PATHS);

        if (found_count == 0) {
            DEBUG_PRINT("  no folders found for template ~%s", templates[t].subpath);
            continue;
        }

        DEBUG_PRINT("  found %d folders for template ~%s", found_count, templates[t].subpath);

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
                    strcpy(entry->allowed_paths[j], templates[t].allowed_paths[j]);
                    entry->allowed_count++;
                }

                if (entry->inode != 0) {
                    SYSLOG_INFO("  New folder found from template: %s (inode: %lu)",
                                entry->path, (unsigned long)entry->inode);
                    if (load_entry_to_bpf(obj, entry, entry_count) == 0) {
                        found_new = 1;
                    }
                } else {
                    SYSLOG_WARN("  New folder found but not exists: %s", entry->path);
                }

                entry_count++;
                free(found_paths[i]);
                total_found++;
            } else {
                SYSLOG_WARN("Max entries reached, cannot add %s", found_paths[i]);
                free(found_paths[i]);
            }
        }
    }

    if (found_new) {
        reload_all_entries(obj);
    }

    return total_found;
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

    FILE *fp = popen("find /usr/local /opt -name 'app_data_sec.bpf.o' 2>/dev/null | head -1", "r");
    if (fp) {
        char result[PATH_MAX];
        if (fgets(result, sizeof(result), fp) != NULL) {
            size_t len = strlen(result);
            if (len > 0 && result[len-1] == '\n') {
                result[len-1] = '\0';
            }
            if (len > 0 && stat(result, &st) == 0 && S_ISREG(st.st_mode)) {
                strcpy(path, result);
                pclose(fp);
                SYSLOG_INFO("Found BPF object via find: %s", path);
                return path;
            }
        }
        pclose(fp);
    }

    SYSLOG_ERR("BPF object file not found!");
    SYSLOG_ERR("Searched paths:");
    for (int i = 0; paths[i] != NULL; i++) {
        SYSLOG_ERR("  - %s", paths[i]);
    }
    SYSLOG_ERR("Please build the BPF program first:");
    SYSLOG_ERR("  clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c app_data_sec.bpf.c -o app_data_sec.bpf.o");
    SYSLOG_ERR("  sudo mkdir -p /usr/local/lib/app_data_sec");
    SYSLOG_ERR("  sudo cp app_data_sec.bpf.o /usr/local/lib/app_data_sec/");

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
    int waiting_for_config = 0;

    openlog("app_data_sec_loader", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    SYSLOG_INFO("APP DATA SEC LOADER STARTING (PID: %d)", getpid());

    DEBUG_PRINT("main: start");

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

    DEBUG_PRINT("main: before memset");

    memset(entries, 0, sizeof(entries));
    memset(templates, 0, sizeof(templates));
    entry_count = 0;
    template_count = 0;
    config_enabled = 0;
    config_mtime = 0;

    DEBUG_PRINT("main: before parse_config");

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

    DEBUG_PRINT("main: after parse_config, enabled=%d, count=%d, templates=%d",
                config_enabled, entry_count, template_count);

    if (!config_enabled || entry_count == 0) {
        if (!config_enabled) {
            SYSLOG_INFO("Config: module disabled, waiting for enable...");
        } else {
            SYSLOG_WARN("No valid protect entries found, waiting for config changes...");
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

        bpf_object__for_each_program(prog, g_bpf_obj) {
            const char *name = bpf_program__name(prog);
            if (strncmp(name, "block_", 6) != 0) continue;

            struct bpf_link *link = bpf_program__attach_lsm(prog);
            if (link) {
                SYSLOG_INFO("Attached: %s (waiting for config)", name);
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

        SYSLOG_INFO("eBPF LSM programs attached (waiting for valid config)");

        waiting_for_config = 1;

        while (1) {
            sleep(CHECK_INTERVAL);

            if (config_changed()) {
                SYSLOG_INFO("Config changed! Checking...");

                memset(entries, 0, sizeof(entries));
                memset(templates, 0, sizeof(templates));
                entry_count = 0;
                template_count = 0;
                config_enabled = 0;
                config_mtime = 0;

                parse_config();

                if (config_enabled && entry_count > 0) {
                    SYSLOG_INFO("Valid config found! Loading entries...");
                    waiting_for_config = 0;

                    err = reload_all_entries(g_bpf_obj);
                    if (err) {
                        SYSLOG_ERR("Failed to load entries: %d", err);
                    } else {
                        SYSLOG_INFO("Config loaded successfully!");
                    }
                    break;
                } else {
                    if (!config_enabled) {
                        SYSLOG_INFO("Config: still disabled");
                    } else {
                        SYSLOG_INFO("No valid protect entries yet, waiting...");
                    }
                }
            }
        }
    }

    if (!waiting_for_config) {
        if (!g_bpf_obj) {
            g_bpf_obj = bpf_object__open_file(bpf_file, NULL);
            if (libbpf_get_error(g_bpf_obj)) {
                SYSLOG_ERR("Failed to open BPF object %s: %s", bpf_file, strerror(-libbpf_get_error(g_bpf_obj)));
                goto cleanup;
            }

            err = bpf_object__load(g_bpf_obj);
            if (err) {
                SYSLOG_ERR("Failed to load BPF object: %d", err);
                goto cleanup;
            }

            err = reload_all_entries(g_bpf_obj);
            if (err) {
                goto cleanup;
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
                int old_inodes_count = 0;
                for (int i = 0; i < entry_count; i++) {
                    if (entries[i].inode != 0 && entries[i].is_active) {
                        old_inodes[old_inodes_count++] = entries[i].inode;
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
                    while (1) {
                        sleep(CHECK_INTERVAL);
                        if (config_changed()) {
                            SYSLOG_INFO("Config changed, rechecking...");
                            break;
                        }
                    }
                    continue;
                }

                if (entry_count == 0) {
                    SYSLOG_WARN("No entries in config, waiting...");
                    continue;
                }

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
                            SYSLOG_INFO("Removing old inode: %lu", (unsigned long)old_inodes[i]);
                            remove_entry_from_bpf(g_bpf_obj, old_inodes[i]);
                        }
                    }
                }

                reload_all_entries(g_bpf_obj);
                last_folder_check = time(NULL);
            }

            if (now - last_folder_check >= RETRY_INTERVAL) {
                DEBUG_PRINT("checking for new folders...");

                int found_new = 0;
                for (int i = 0; i < entry_count; i++) {
                    if (entries[i].path[0] == '\0') continue;
                    if (entries[i].is_active && entries[i].inode != 0) continue;

                    __u64 current_inode = get_inode_from_path(entries[i].path);
                    if (current_inode == 0) {
                        DEBUG_PRINT("  %s - still not exists", entries[i].path);
                        continue;
                    }

                    entries[i].inode = current_inode;
                    entries[i].is_active = 1;
                    entries[i].last_check = time(NULL);

                    SYSLOG_INFO("New folder found: %s (inode: %lu)",
                                entries[i].path, (unsigned long)current_inode);

                    if (load_entry_to_bpf(g_bpf_obj, &entries[i], i) == 0) {
                        found_new = 1;
                    }
                }

                int found_recreated = 0;
                for (int i = 0; i < entry_count; i++) {
                    if (entries[i].path[0] == '\0') continue;
                    if (!entries[i].is_active || entries[i].inode == 0) continue;

                    __u64 current_inode = get_inode_from_path(entries[i].path);
                    if (current_inode == 0) {
                        SYSLOG_INFO("Folder removed from filesystem: %s", entries[i].path);
                        remove_entry_from_bpf(g_bpf_obj, entries[i].inode);
                        entries[i].inode = 0;
                        entries[i].is_active = 0;
                        found_recreated = 1;
                    } else if (entries[i].inode != current_inode) {
                        SYSLOG_INFO("Folder recreated: %s (old inode: %lu, new inode: %lu)",
                                    entries[i].path, (unsigned long)entries[i].inode, (unsigned long)current_inode);
                        remove_entry_from_bpf(g_bpf_obj, entries[i].inode);
                        entries[i].inode = current_inode;
                        entries[i].is_active = 1;
                        load_entry_to_bpf(g_bpf_obj, &entries[i], i);
                        found_recreated = 1;
                    }
                }

                int found_from_templates = scan_templates_and_load(g_bpf_obj);

                if (found_new || found_recreated || found_from_templates) {
                    reload_all_entries(g_bpf_obj);
                }

                last_folder_check = now;
            }
        }
    }

    cleanup:
    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
    }
    SYSLOG_INFO("APP DATA SEC LOADER EXITING");
    closelog();
    printf("Exit\n");
    return err;
}
