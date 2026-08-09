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

#define CONFIG_PATH "/etc/app_data_sec.conf"
#define MAX_LINE_LEN 1024
#define MAX_PATHS 100
#define MAX_ALLOWED 10

struct protect_entry {
    char path[PATH_MAX];
    __u64 inode;
    __u64 allowed_inodes[MAX_ALLOWED];
    int allowed_count;
    int is_expanded;
};

struct protect_entry entries[MAX_PATHS];
int entry_count = 0;
int config_enabled = 0;

static __u64 get_inode_from_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return st.st_ino;
}

// Функция для поиска всех пользователей и разворачивания ~
static int expand_for_all_users(const char *pattern, char **expanded_paths, int *count) {
    struct passwd *pw;
    int idx = 0;

    if (pattern[0] != '~') {
        expanded_paths[idx] = strdup(pattern);
        if (expanded_paths[idx]) {
            idx++;
        }
        *count = idx;
        return 0;
    }

    const char *subpath = pattern + 1;

    setpwent();
    while ((pw = getpwent()) != NULL && idx < MAX_PATHS) {
        if (!pw->pw_dir || pw->pw_dir[0] != '/') {
            continue;
        }

        // Проверяем, что это реальный пользователь (UID >= 1000)
        if (pw->pw_uid < 1000) {
            continue;
        }

        // Проверяем, что домашняя директория начинается с /home/
        if (strncmp(pw->pw_dir, "/home/", 6) != 0) {
            continue;
        }

        char expanded[PATH_MAX];
        snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
        expanded_paths[idx] = strdup(expanded);
        if (expanded_paths[idx]) {
            idx++;
        }
    }
    endpwent();

    *count = idx;
    return 0;
}

static int parse_config(void) {
    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Config file %s not found\n", CONFIG_PATH);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int line_num = 0;
    entry_count = 0;
    config_enabled = 0;

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
                    config_enabled = 1;
                    printf("Config: enabled=yes\n");
                } else {
                    config_enabled = 0;
                    printf("Config: enabled=no\n");
                }
            }
            continue;
        }

        if (strncmp(start, "protect", 7) == 0) {
            char *ptr = start + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                fprintf(stderr, "Config line %d: missing path after protect\n", line_num);
                continue;
            }

            char path[PATH_MAX];
            char *path_end = ptr;
            while (*path_end && *path_end != ' ' && *path_end != '\t') path_end++;

            size_t path_len = path_end - ptr;
            if (path_len >= sizeof(path)) {
                path_len = sizeof(path) - 1;
            }
            strncpy(path, ptr, path_len);
            path[path_len] = '\0';

            char *allowed[MAX_ALLOWED];
            int allowed_count = 0;

            ptr = path_end;
            while (*ptr) {
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (*ptr == '\0') break;

                char *arg_end = ptr;
                while (*arg_end && *arg_end != ' ' && *arg_end != '\t') arg_end++;

                size_t arg_len = arg_end - ptr;
                if (arg_len > 0 && allowed_count < MAX_ALLOWED) {
                    allowed[allowed_count] = malloc(arg_len + 1);
                    strncpy(allowed[allowed_count], ptr, arg_len);
                    allowed[allowed_count][arg_len] = '\0';
                    allowed_count++;
                }

                ptr = arg_end;
            }

            char *expanded_paths[MAX_PATHS];
            int expanded_count = 0;

            if (path[0] == '~') {
                expand_for_all_users(path, expanded_paths, &expanded_count);
            } else {
                expanded_paths[0] = strdup(path);
                expanded_count = 1;
            }

            for (int i = 0; i < expanded_count && entry_count < MAX_PATHS; i++) {
                struct protect_entry *entry = &entries[entry_count];
                strncpy(entry->path, expanded_paths[i], sizeof(entry->path) - 1);
                entry->path[sizeof(entry->path) - 1] = '\0';

                entry->inode = get_inode_from_path(entry->path);
                if (entry->inode == 0) {
                    fprintf(stderr, "Warning: Path '%s' does not exist, skipping\n", entry->path);
                    free(expanded_paths[i]);
                    continue;
                }
                entry->allowed_count = 0;

                for (int j = 0; j < allowed_count && j < MAX_ALLOWED; j++) {
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

                entry->is_expanded = 1;
                printf("Config: protect %s (inode: %lu)\n", entry->path, (unsigned long)entry->inode);
                entry_count++;
                free(expanded_paths[i]);
            }

            for (int j = 0; j < allowed_count; j++) {
                free(allowed[j]);
            }
        }
    }

    fclose(fp);
    return 0;
}

// ============================================================================
// ФУНКЦИЯ load_entries_to_bpf
// ============================================================================

static int load_entries_to_bpf(struct bpf_object *obj) {
    struct bpf_map *map;
    int err;
    __u32 key;
    int fd;

    if (entry_count == 0) {
        printf("No entries to load\n");
        return 0;
    }

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

    int loaded = 0;
    printf("Loading %d entries to BPF map...\n", entry_count);

    for (int i = 0; i < entry_count && i < MAX_PATHS; i++) {
        key = i;
        err = bpf_map_update_elem(fd, &key, &entries[i].inode, BPF_ANY);
        if (err < 0) {
            fprintf(stderr, "Failed to update target_inode_map[%d]: %d (inode: %lu, path: %s)\n",
                    i, err, (unsigned long)entries[i].inode, entries[i].path);
        } else {
            printf("  [%d] Loaded inode: %lu (path: %s)\n",
                   i, (unsigned long)entries[i].inode, entries[i].path);
            loaded++;
        }
    }

    if (entries[0].allowed_count > 0) {
        map = bpf_object__find_map_by_name(obj, "allowed_inode_map");
        if (map) {
            fd = bpf_map__fd(map);
            if (fd >= 0) {
                key = 0;
                err = bpf_map_update_elem(fd, &key, &entries[0].allowed_inodes[0], BPF_ANY);
                if (err < 0) {
                    fprintf(stderr, "Failed to update allowed_inode_map: %d\n", err);
                } else {
                    printf("Loaded allowed inode: %lu\n", (unsigned long)entries[0].allowed_inodes[0]);
                }
            }
        }
    }

    printf("Total loaded: %d entries\n", loaded);
    return 0;
}

// ============================================================================
// ПЕЧАТЬ ПОМОЩИ
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -l, --log-level <0-2>  Set log level (0=off, 1=blocked only, 2=everything, default=2)\n");
    fprintf(stderr, "  -h, --help             Show this help\n");
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int err;
    int log_level = 2;
    const char *bpf_file = "app_data_sec.bpf.o";

    // Парсим аргументы
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

    // Сохраняем log_level в переменную для вывода
    int requested_log_level = log_level;

    printf("Loading config from %s\n", CONFIG_PATH);
    parse_config();

    if (!config_enabled) {
        printf("Config: module disabled, exiting\n");
        return 0;
    }

    if (entry_count == 0) {
        printf("No valid protect entries found, exiting\n");
        return 0;
    }

    obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object %s\n", bpf_file);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = load_entries_to_bpf(obj);
    if (err) {
        goto cleanup;
    }

    // Устанавливаем уровень логирования в BPF карту
    map = bpf_object__find_map_by_name(obj, "log_level_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 key = 0;
            __u32 log_level_val = requested_log_level;
            err = bpf_map_update_elem(fd, &key, &log_level_val, BPF_ANY);
            if (err < 0) {
                fprintf(stderr, "Failed to update log_level_map: %d\n", err);
            }
        }
    } else {
        fprintf(stderr, "Warning: log_level_map not found\n");
    }

    // Прикрепляем LSM программы
    bpf_object__for_each_program(prog, obj) {
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
    printf("Press Ctrl-C to stop...\n");

    while (1) {
        sleep(1);
    }

    cleanup:
    if (obj) {
        bpf_object__close(obj);
    }
    return err;
}
