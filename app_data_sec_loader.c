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
        if (pw->pw_dir && pw->pw_dir[0] == '/') {
            char expanded[PATH_MAX];
            snprintf(expanded, sizeof(expanded), "%s%s", pw->pw_dir, subpath);
            expanded_paths[idx] = strdup(expanded);
            if (expanded_paths[idx]) {
                idx++;
            }
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
// ОСНОВНАЯ ФУНКЦИЯ
// ============================================================================

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int err;
    int log_level = 2;
    const char *bpf_file = "app_data_sec.bpf.o";

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

    // Открываем BPF объект напрямую
    obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object %s\n", bpf_file);
        return 1;
    }

    // Загружаем BPF программу
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // Находим карты
    map = bpf_object__find_map_by_name(obj, "target_inode_map");
    if (!map) {
        fprintf(stderr, "Failed to find target_inode_map\n");
        goto cleanup;
    }

    // Загружаем данные в карту
    __u32 key = 0;
    struct protect_entry *first = &entries[0];
    int fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }

    err = bpf_map_update_elem(fd, &key, &first->inode, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "Failed to update target_inode_map: %d\n", err);
        goto cleanup;
    }
    printf("Loaded target inode: %lu\n", (unsigned long)first->inode);

    // Разрешенная программа
    if (first->allowed_count > 0) {
        map = bpf_object__find_map_by_name(obj, "allowed_inode_map");
        if (map) {
            fd = bpf_map__fd(map);
            if (fd >= 0) {
                err = bpf_map_update_elem(fd, &key, &first->allowed_inodes[0], BPF_ANY);
                if (err < 0) {
                    fprintf(stderr, "Failed to update allowed_inode_map: %d\n", err);
                } else {
                    printf("Loaded allowed inode: %lu\n", (unsigned long)first->allowed_inodes[0]);
                }
            }
        }
    }

    // Уровень логирования
    map = bpf_object__find_map_by_name(obj, "log_level_map");
    if (map) {
        fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 log_level_val = log_level;
            bpf_map_update_elem(fd, &key, &log_level_val, BPF_ANY);
        }
    }

    // Прикрепляем LSM программы
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);

        // Пропускаем программы, которые не являются LSM
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
    printf("Log level: %d\n", log_level);
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
