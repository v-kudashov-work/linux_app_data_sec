// app_data_sec_loader.c - С полным логированием синхронизации
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
#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

// ============================================================================
// НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ
// ============================================================================
#define VERSION "0.5.4"
#define VERSION_DATE "2026-08-19"

#define CONFIG_PATH "/etc/app_data_sec.conf"
#define PID_FILE "/run/app_data_sec_loader.pid"
#define MAX_LINE_LEN 1024
#define MAX_PATHS 5000
#define MAX_ALLOWED 20
#define MAX_PATH_LEN 256
#define CHECK_INTERVAL 5
#define RETRY_INTERVAL 15
#define AUTOCONFIG_DIR "/etc/app_data_sec.autoconfig"
#define AUTOCONFIG_TIMESTAMP "/etc/app_data_sec.autoconfig.timestamp"
#define AUTOCONFIG_CHECK_INTERVAL 900  // 15 минут
#define MOUNT_CHECK_INTERVAL 0
#define HOME_SCAN_INTERVAL 0
#define MAX_SCAN_MOUNT_PATHS 500        // Максимальное количество путей для scan_mount
#define HOME_PATH "/home/"            // Путь к домашним директориям
#define MAX_HOME_USERS 1000 //Максимальное количество папок в папке /home/ (количество пользователей)

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ ОТСЛЕЖИВАНИЯ ПОЛЬЗОВАТЕЛЕЙ
// ============================================================================

static char processed_home_users[MAX_HOME_USERS][MAX_PATH_LEN];
static int processed_home_users_count = 0;

// ============================================================================
// ОТЛАДКА
// ============================================================================
// #define DEBUG_ENABLED 1

#ifdef DEBUG_ENABLED
#define DEBUG_PRINT(fmt, ...) \
do { \
    printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    fflush(stdout); \
} while (0)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

// Глобальный флаг для выхода
static volatile int keep_running = 1;

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

//    printf("%s\n", buffer);
    fflush(stdout);
}

#define SYSLOG_ERR(fmt, ...) log_to_syslog(LOG_ERR, "[ERROR] " fmt, ##__VA_ARGS__)
#define SYSLOG_WARN(fmt, ...) log_to_syslog(LOG_WARNING, "[WARNING] " fmt, ##__VA_ARGS__)
#define SYSLOG_INFO(fmt, ...) log_to_syslog(LOG_INFO, "[INFO] " fmt, ##__VA_ARGS__)

#ifdef DEBUG_ENABLED
#define SYSLOG_INFO_D(fmt, ...) log_to_syslog(LOG_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define SYSLOG_WARN_D(fmt, ...) log_to_syslog(LOG_WARNING, "[WARNING] " fmt, ##__VA_ARGS__)
#else
#define SYSLOG_INFO_D(fmt, ...) ((void)0)
#define SYSLOG_WARN_D(fmt, ...) ((void)0)
#endif

// ============================================================================
// ОПТИМИЗИРОВАННЫЕ СТРУКТУРЫ
// ============================================================================

struct folder_program_key {
    __u64 folder_inode;
    __u32 prog_idx;
} __attribute__((packed));

struct protected_folder_config {
    __u64 folder_inode;
    __u32 allowed_program_count;
};

struct protect_entry {
    char path[MAX_PATH_LEN];
    __u64 inode;
    __u64 allowed_inodes[MAX_ALLOWED];
    char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];
    int allowed_count;
    int is_active;
    time_t last_check;
    int is_home;                    // 1 если путь начинается с ~, 0 если точный
};

struct protect_template {
    char pattern[MAX_PATH_LEN];
    char subpath[MAX_PATH_LEN];
    __u64 allowed_inodes[MAX_ALLOWED];
    char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];
    int allowed_count;
//    int enabled;
    int is_home;
};

static struct protect_entry entries[MAX_PATHS];
static struct protect_template templates[MAX_PATHS];

static int entry_count = 0;
static int template_count = 0;
static int config_enabled = 0;
static time_t config_mtime = 0;

// ============================================================================
// СТРУКТУРЫ ДЛЯ SCAN_MOUNT
// ============================================================================

struct scan_mount_entry {
    char path[MAX_PATH_LEN];
    char original_pattern[MAX_PATH_LEN];
    int is_home;
    char subpath[MAX_PATH_LEN];
    int is_mounted;
    time_t last_check;
};

static struct scan_mount_entry scan_mount_paths[MAX_SCAN_MOUNT_PATHS];
static int scan_mount_path_count = 0;

// ============================================================================
// ИЗМЕНЕНИЕ 2: ДОБАВЛЯЕМ МЬЮТЕКС ДЛЯ СИНХРОНИЗАЦИИ
// ============================================================================
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// ПРОТОТИПЫ ФУНКЦИЙ
// ============================================================================

static int add_folder_to_entries(struct bpf_object *obj, struct protect_entry *new_entry);
static int remove_folder_from_entries(struct bpf_object *obj, int entry_idx);
static int remove_program_from_entry(struct bpf_object *obj, int entry_idx, int prog_idx);
static int disable_program_from_ebpf(struct bpf_object *obj, int entry_idx, int prog_idx);
static int clear_all_entries(struct bpf_object *obj);
static int sync_config_to_entries(struct bpf_object *obj,
                                  struct protect_entry *temp_entries, int temp_count,
                                  struct protect_template *temp_templates, int temp_template_count,
                                  int temp_config_enabled);
static int parse_config_to_temp(struct protect_entry **temp_entries, int *temp_count,
                                struct protect_template **temp_templates, int *temp_template_count,
                                int *temp_config_enabled);
static int load_single_entry(struct bpf_object *obj, struct protect_entry *entry);
static int scan_templates_and_load(struct bpf_object *obj);
static int config_changed(void);
static const char* find_bpf_object(void);
static int parse_scan_mount(const char *line);
static int check_scan_mount_paths(void);
static int is_home_user_processed(const char *username);
static void add_processed_home_user(const char *username);
//static void clear_processed_home_users(void);
static int check_new_home_directories(struct bpf_object *obj, int without_rescan);
static void perform_full_scan(struct bpf_object *obj);

// ============================================================================
// БЕЗОПАСНОЕ КОПИРОВАНИЕ СТРОК
// ============================================================================

static int parse_quoted_string(const char **ptr, char *buffer, size_t buffer_size) {
    if (!ptr || !*ptr || !buffer || buffer_size == 0) return -1;

    const char *p = *ptr;

    // Пропускаем пробелы
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '\0') return -1;

    char quote_char = 0;
    int is_quoted = 0;

    // Проверяем, начинается ли строка с кавычки
    if (*p == '"' || *p == '\'') {
        quote_char = *p;
        is_quoted = 1;
        p++; // Пропускаем открывающую кавычку
    }

    int pos = 0;
    while (*p != '\0') {
        if (is_quoted) {
            if (*p == quote_char) {
                // Закрывающая кавычка
                p++;
                break;
            }
            // Внутри кавычек разрешаем пробелы
            if (pos < (int)buffer_size - 1) {
                buffer[pos++] = *p;
            }
            p++;
        } else {
            // Без кавычек - останавливаемся на пробеле или табе
            if (*p == ' ' || *p == '\t') {
                break;
            }
            if (pos < (int)buffer_size - 1) {
                buffer[pos++] = *p;
            }
            p++;
        }
    }
    buffer[pos] = '\0';

    // Пропускаем пробелы после строки
    while (*p == ' ' || *p == '\t') p++;

    *ptr = p;
    return 0;
}

static void safe_strcpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) return;
    size_t src_len = strnlen(src, size - 1);
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
}

// ============================================================================
// ФУНКЦИИ РАБОТЫ С ФАЙЛОВОЙ СИСТЕМОЙ
// ============================================================================

static int is_home_path(const char *path) {
    if (!path) return 0;
    return (path[0] == '~');
}

static __u64 get_inode_from_path(const char *path) {
    SYSLOG_INFO_D("get_inode_from_path  Path: %s", path);

    if (!path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;

    SYSLOG_INFO_D("get_inode_from_path id: %i", st.st_ino);
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

    if (!subpath || !found_paths || max_paths == 0) return 0;

    //Добавление папок в home для существующих пользователей
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
//            SYSLOG_INFO("=========> Add home Path: %s", found_paths[idx]);
            if (found_paths[idx]) idx++;
        }
    }
    endpwent();

    //Добавление остальных папок в home
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
// ОПЕРАЦИЯ 1: ДОБАВЛЕНИЕ ПАПКИ В ENTRIES И BPF
// ============================================================================

static int add_folder_to_entries(struct bpf_object *obj, struct protect_entry *new_entry) {
    if (!new_entry || new_entry->inode == 0) {
        SYSLOG_ERR("Empty entry for add_folder_to_entries");
        return -1;
    }

    SYSLOG_INFO_D("=== ADD FOLDER ===");
    SYSLOG_INFO_D("  Path: %s", new_entry->path);
    SYSLOG_INFO_D("  Inode: %lu", (unsigned long)new_entry->inode);
    SYSLOG_INFO_D("  Programs count: %d", new_entry->allowed_count);

    // Проверяем, существует ли уже такая папка
    for (int i = 0; i < entry_count; i++) {
        if (entries[i].inode == new_entry->inode) {
            SYSLOG_WARN_D("Folder already exists: %s (inode: %lu)",
                          new_entry->path, (unsigned long)new_entry->inode);
            return 0;
        }
    }

    if (entry_count >= MAX_PATHS) {
        SYSLOG_ERR("Max entries reached, cannot add: %s", new_entry->path);
        return -1;
    }

    SYSLOG_INFO_D("Adding folder to entries[%d]", entry_count);
    // Добавляем в entries
    memcpy(&entries[entry_count], new_entry, sizeof(struct protect_entry));
    entry_count++;

    // Добавляем в BPF
    if (obj) {
        struct bpf_map *map;
        int fd;

        SYSLOG_INFO_D("Adding folder to BPF...");

        // Добавляем папку в folder_config_map
        map = bpf_object__find_map_by_name(obj, "folder_config_map");
        if (map) {
            fd = bpf_map__fd(map);
            if (fd >= 0) {
                struct protected_folder_config config = {
                        .folder_inode = new_entry->inode,
                        .allowed_program_count = new_entry->allowed_count,
                };
                if (bpf_map_update_elem(fd, &new_entry->inode, &config, BPF_ANY) < 0) {
                    SYSLOG_ERR("Failed to add folder to BPF: %s", new_entry->path);
                } else {
                    SYSLOG_INFO("Added folder: %s (inode: %lu, programs: %d)",
                                new_entry->path, (unsigned long)new_entry->inode, new_entry->allowed_count);
                }
            }
        }

        // Добавляем программы
        map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
        if (map) {
            fd = bpf_map__fd(map);
            if (fd >= 0) {
                for (int j = 0; j < new_entry->allowed_count && j < MAX_ALLOWED; j++) {
                    struct folder_program_key key = {
                            .folder_inode = new_entry->inode,
                            .prog_idx = j
                    };
                    __u64 value = new_entry->allowed_inodes[j];
                    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) < 0) {
                        SYSLOG_ERR("  Failed to add program %d to BPF", j);
                    } else {
                        SYSLOG_INFO("  Added program %d: %s (inode: %lu)",
                                    j, new_entry->allowed_paths[j], (unsigned long)value);
                    }
                }
            }
        }
    }

    SYSLOG_INFO_D("=== ADD FOLDER COMPLETE ===");
    return 0;
}

// ============================================================================
// ОПЕРАЦИЯ 2: УДАЛЕНИЕ ПРОГРАММЫ ИЗ ENTRIES И BPF
// ============================================================================

static int remove_program_from_entry(struct bpf_object *obj, int entry_idx, int prog_idx) {
    if (entry_idx < 0 || entry_idx >= entry_count) {
        SYSLOG_ERR("Invalid entry index: %d", entry_idx);
        return -1;
    }

    if (prog_idx < 0 || prog_idx >= entries[entry_idx].allowed_count) {
        SYSLOG_ERR("Invalid program index: %d", prog_idx);
        return -1;
    }

    __u64 folder_inode = entries[entry_idx].inode;
    __u64 program_inode = entries[entry_idx].allowed_inodes[prog_idx];
    char *path = entries[entry_idx].path;

    SYSLOG_INFO_D("=== REMOVE PROGRAM ===");
    SYSLOG_INFO_D("  Folder: %s (inode: %lu)", path, (unsigned long)folder_inode);
    SYSLOG_INFO_D("  Program: %s (inode: %lu)",
                  entries[entry_idx].allowed_paths[prog_idx], (unsigned long)program_inode);

    // Удаляем из BPF
    if (obj) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                struct folder_program_key key = {
                        .folder_inode = folder_inode,
                        .prog_idx = prog_idx
                };
                if (bpf_map_delete_elem(fd, &key) < 0) {
                    SYSLOG_ERR("  Failed to remove program from BPF");
                } else {
                    SYSLOG_INFO_D("  Program removed from BPF");
                }
            }
        }
    }

    // Удаляем из entries (сдвигаем)
    for (int i = prog_idx; i < entries[entry_idx].allowed_count - 1; i++) {
        entries[entry_idx].allowed_inodes[i] = entries[entry_idx].allowed_inodes[i + 1];
        strcpy(entries[entry_idx].allowed_paths[i], entries[entry_idx].allowed_paths[i + 1]);
    }
    entries[entry_idx].allowed_count--;

    SYSLOG_INFO("Removed program from %s: %s (inode: %lu)",
                path, entries[entry_idx].allowed_paths[prog_idx], (unsigned long)program_inode);

    // Если программ не осталось - удаляем всю папку
    // if (entries[entry_idx].allowed_count == 0) {
    //     SYSLOG_INFO_D("No programs left in %s, removing folder", path);
    //     remove_folder_from_entries(obj, entry_idx);
    // }

    SYSLOG_INFO_D("=== REMOVE PROGRAM COMPLETE ===");
    return 0;
}

static int disable_program_from_ebpf(struct bpf_object *obj, int entry_idx, int prog_idx) {
    if (entry_idx < 0 || entry_idx >= entry_count) {
        SYSLOG_ERR("Invalid entry index: %d", entry_idx);
        return -1;
    }

    if (prog_idx < 0 || prog_idx >= entries[entry_idx].allowed_count) {
        SYSLOG_ERR("Invalid program index: %d", prog_idx);
        return -1;
    }

    __u64 folder_inode = entries[entry_idx].inode;
    __u64 program_inode = entries[entry_idx].allowed_inodes[prog_idx];
    char *path = entries[entry_idx].path;

    SYSLOG_INFO_D("=== DISABLE PROGRAM ===");
    SYSLOG_INFO_D("  Folder: %s (inode: %lu)", path, (unsigned long)folder_inode);
    SYSLOG_INFO_D("  Program: %s (inode: %lu)",
                  entries[entry_idx].allowed_paths[prog_idx], (unsigned long)program_inode);

    // Удаляем из BPF
    if (obj) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                struct folder_program_key key = {
                        .folder_inode = folder_inode,
                        .prog_idx = prog_idx
                };
                if (bpf_map_delete_elem(fd, &key) < 0) {
                    SYSLOG_ERR("  Failed to remove program from BPF");
                } else {
                    SYSLOG_INFO_D("  Program removed from BPF");
                }
            }
        }
    }

    entries[entry_idx].allowed_inodes[prog_idx] = 0;

    SYSLOG_INFO("Disble program from %s: %s (inode: %lu)",
                path, entries[entry_idx].allowed_paths[prog_idx], (unsigned long)program_inode);

    SYSLOG_INFO_D("=== DISABLE PROGRAM COMPLETE ===");
    return 0;
}

// ============================================================================
// ОПЕРАЦИЯ 3: УДАЛЕНИЕ ПАПКИ ИЗ ENTRIES И BPF
// ============================================================================

static int remove_folder_from_entries(struct bpf_object *obj, int entry_idx) {
    if (entry_idx < 0 || entry_idx >= entry_count) {
        SYSLOG_ERR("Invalid entry index: %d", entry_idx);
        return -1;
    }

    __u64 folder_inode = entries[entry_idx].inode;

#ifdef DEBUG_ENABLED
    char *path = entries[entry_idx].path;

    SYSLOG_INFO_D("=== REMOVE FOLDER ===");
    SYSLOG_INFO_D("  Path: %s", path);
    SYSLOG_INFO_D("  Inode: %lu", (unsigned long)folder_inode);
    SYSLOG_INFO_D("  Programs: %d", entries[entry_idx].allowed_count);
#endif

    // Удаляем из BPF
    if (obj) {
        // Удаляем папку из folder_config_map
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_config_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                if (bpf_map_delete_elem(fd, &folder_inode) < 0) {
                    SYSLOG_ERR("  Failed to remove folder from folder_config_map");
                } else {
                    SYSLOG_INFO_D("  Folder removed from folder_config_map");
                }
            }
        }

        // Удаляем все программы
        map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                for (int i = 0; i < MAX_ALLOWED; i++) {
                    struct folder_program_key key = {
                            .folder_inode = folder_inode,
                            .prog_idx = i
                    };
                    bpf_map_delete_elem(fd, &key);
                }
                SYSLOG_INFO_D("  All programs removed from BPF");
            }
        }
    }

    // Удаляем из entries (сдвигаем)
    for (int i = entry_idx; i < entry_count - 1; i++) {
        memcpy(&entries[i], &entries[i + 1], sizeof(struct protect_entry));
    }
    memset(&entries[entry_count - 1], 0, sizeof(struct protect_entry));
    entry_count--;

    SYSLOG_INFO("  Folder removed from entries, remaining: %d", entry_count);
    SYSLOG_INFO_D("=== REMOVE FOLDER COMPLETE ===");
    return 0;
}


// ============================================================================
// АТОМАРНОЕ ДОБАВЛЕНИЕ ПРОГРАММЫ В ENTRIES И BPF (ПО УКАЗАТЕЛЮ НА ENTRY)
// ============================================================================

static int add_program_to_folder(struct bpf_object *obj, struct protect_entry *entry,
                                 __u64 program_inode, const char *program_path) {
    if (!entry || program_inode == 0 || !program_path) {
        SYSLOG_ERR("Invalid parameters for add_program_to_folder");
        return -1;
    }

    if (!program_path || program_path[0] == '\0') {
        SYSLOG_ERR("Empty program path");
        return -1;
    }

    // Проверяем, не превышен ли лимит программ
    if (entry->allowed_count >= MAX_ALLOWED) {
        SYSLOG_ERR("Max programs reached for folder %s (%d/%d)",
                   entry->path, entry->allowed_count, MAX_ALLOWED);
        return -1;
    }

    // Проверяем, не существует ли уже такая программа
    for (int i = 0; i < entry->allowed_count; i++) {
        if (entry->allowed_inodes[i] == program_inode) {
            SYSLOG_WARN_D("Program already exists in %s: %s (inode: %lu)",
                          entry->path, program_path, (unsigned long)program_inode);
            return 0;
        }
    }

    __u64 folder_inode = entry->inode;
    int new_idx = entry->allowed_count;

    SYSLOG_INFO_D("Adding program to folder %s: %s (inode: %lu)",
                  entry->path, program_path, (unsigned long)program_inode);

    // 1. Добавляем в BPF (если объект существует)
    if (obj) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                struct folder_program_key key = {
                        .folder_inode = folder_inode,
                        .prog_idx = new_idx
                };
                int err = bpf_map_update_elem(fd, &key, &program_inode, BPF_ANY);
                if (err < 0) {
                    SYSLOG_ERR("  Failed to add program to BPF: %d", err);
                    return -1;
                }
                SYSLOG_INFO_D("  Program added to BPF: key (folder=%llu, idx=%d), value=%llu",
                              (unsigned long long)folder_inode,
                              new_idx, (unsigned long long)program_inode);
            }
        }
    }

    // 2. Добавляем в entries
    entry->allowed_inodes[new_idx] = program_inode;
    safe_strcpy(entry->allowed_paths[new_idx], program_path, MAX_PATH_LEN);
    entry->allowed_count++;

    // 3. Обновляем конфигурацию папки в BPF (увеличиваем счетчик программ)
    if (obj) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_config_map");
        if (map) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                struct protected_folder_config config = {
                        .folder_inode = folder_inode,
                        .allowed_program_count = entry->allowed_count,
                };
                // Ключ - folder_inode, значение - config
                int err = bpf_map_update_elem(fd, &folder_inode, &config, BPF_ANY);
                if (err < 0) {
                    SYSLOG_ERR("  Failed to update folder config in BPF: %d", err);
                    // Откатываем добавление программы в entries
                    entry->allowed_count--;
                    entry->allowed_inodes[new_idx] = 0;
                    memset(entry->allowed_paths[new_idx], 0, MAX_PATH_LEN);
                    return -1;
                }
                SYSLOG_INFO_D("  Folder config updated: inode=%llu, programs=%d",
                              (unsigned long long)folder_inode, entry->allowed_count);
            }
        }
    }

    SYSLOG_INFO("Added program to %s: %s (inode: %lu)",
                entry->path, program_path, (unsigned long)program_inode);
    return 0;
}

// ============================================================================
// ОПЕРАЦИЯ 4: ОЧИСТКА ВСЕХ ЗАПИСЕЙ
// ============================================================================

static int clear_all_entries(struct bpf_object *obj) {
    SYSLOG_INFO_D("=== CLEAR ALL ENTRIES ===");
    SYSLOG_INFO_D("Current entries: %d", entry_count);

    while (entry_count > 0) {
        remove_folder_from_entries(obj, entry_count - 1);
    }

    entry_count = 0;

//    memset(templates, 0, sizeof(templates));
//    template_count = 0;
//    config_enabled = 0;

    // struct stat st;
    // if (stat(CONFIG_PATH, &st) == 0) {
    //     config_mtime = st.st_mtime;
    // }

    SYSLOG_INFO("All entries cleared");
    return 0;
}

// ============================================================================
// ОПЕРАЦИЯ 5: СИНХРОНИЗАЦИЯ С КОНФИГОМ
// ============================================================================

static int sync_config_to_entries(struct bpf_object *obj,
                                  struct protect_entry *temp_entries, int temp_count,
                                  struct protect_template *temp_templates, int temp_template_count,
                                  int temp_config_enabled) {
    int i, j, k, found;

    SYSLOG_INFO_D("=== SYNC CONFIG TO ENTRIES ===");
    SYSLOG_INFO_D("Temp entries: %d, Current entries: %d, Config enabled: %d",
                  temp_count, entry_count, temp_config_enabled);

    // ============================================================
    // 1. Обновляем templates
    // ============================================================
    SYSLOG_INFO_D("Step 1: Updating templates...");
    memset(templates, 0, sizeof(templates));
    if (temp_template_count > 0) {
        memcpy(templates, temp_templates, sizeof(struct protect_template) * temp_template_count);
        SYSLOG_INFO_D("Templates updated: %d", temp_template_count);
    }
    template_count = temp_template_count;

    // Если конфиг отключен или нет записей - очищаем всё
    if (!temp_config_enabled || temp_count == 0) {
        SYSLOG_INFO_D("Config disabled or empty, clearing all entries");
        int res = clear_all_entries(obj);

        config_enabled = temp_config_enabled;

        SYSLOG_INFO_D("=== SYNC COMPLETE (cleared) ===");
        return res;
    }

    // ============================================================
    // 2. УДАЛЯЕМ папки, которых нет в temp_entries
    // ============================================================
    SYSLOG_INFO_D("Step 1: Removing folders not in config...");
    for (i = entry_count - 1; i >= 0; i--) {
//        if (entries[i].inode == 0) continue;
        found = 0;
        for (j = 0; j < temp_count; j++) {
            if (temp_entries[j].inode == entries[i].inode && entries[i].inode != 0) {
//            if (temp_entries[j].inode == entries[i].inode) {
                found = 1;
                break;
            }
        }
        if (!found) {
            SYSLOG_INFO_D("Deleting folder not in config: %s (inode: %lu)",
                          entries[i].path, (unsigned long)entries[i].inode);
            remove_folder_from_entries(obj, i);
        }
    }

    // ============================================================
    // 3. ОБНОВЛЯЕМ или ДОБАВЛЯЕМ папки из temp_entries
    // ============================================================
    SYSLOG_INFO_D("Step 2: Updating or adding folders from config...");
    for (i = 0; i < temp_count; i++) {
        found = 0;
        for (j = entry_count - 1; j >= 0; j--) {
            if (temp_entries[i].inode == entries[j].inode) {
                found = 1;
                SYSLOG_INFO_D("Folder exists: %s (inode: %lu)",
                              entries[j].path, (unsigned long)entries[j].inode);

                // Проверяем программы: какие нужно удалить, какие добавить
                // Удаляем программы, которых нет в temp_entries
                for (k = entries[j].allowed_count - 1; k >= 0; k--) {
                    int prog_found = 0;
                    for (int m = 0; m < temp_entries[i].allowed_count; m++) {
                        if (entries[j].allowed_inodes[k] == temp_entries[i].allowed_inodes[m]) {
                            prog_found = 1;
                            break;
                        }
                    }

                    if (!prog_found) {
                        for (int m = 0; m < temp_entries[i].allowed_count; m++) {
                            if (strcmp(entries[j].allowed_paths[k], temp_entries[i].allowed_paths[m]) == 0) {
                                prog_found = 1;
                                break;
                            }
                        }

                        entries[j].allowed_inodes[k] = 0;
                    }

                    if (!prog_found) {
                        SYSLOG_INFO_D("Removing program from %s: %s",
                                      entries[j].path, entries[j].allowed_paths[k]);
                        remove_program_from_entry(obj, j, k);
                    }
                }
                break;
            }
        }

        if (!found) {
            // Новая папка - добавляем
            SYSLOG_INFO_D("Adding new folder: %s (inode: %lu, programs: %d)",
                          temp_entries[i].path, (unsigned long)temp_entries[i].inode,
                          temp_entries[i].allowed_count);
            add_folder_to_entries(obj, &temp_entries[i]);
        }

        // Второй проход для добавления программ
        for (j = entry_count - 1; j >= 0; j--) {
            if (temp_entries[i].inode == entries[j].inode) {
                SYSLOG_INFO_D("Adding new programs to: %s, total count: %i", entries[j].path, entries[j].allowed_count);

                // Добавляем новые программы
                for (k = 0; k < temp_entries[i].allowed_count; k++) {
                    int prog_found = 0;
                    for (int m = 0; m < entries[j].allowed_count; m++) {
                        if (entries[j].allowed_inodes[m] == temp_entries[i].allowed_inodes[k]) {
                            prog_found = 1;
                            break;
                        }
                    }
                    if (!prog_found) {
                        add_program_to_folder(obj, &entries[j],
                                              temp_entries[i].allowed_inodes[k],
                                              temp_entries[i].allowed_paths[k]);
                    }
                }
                break;
            }
        }
    }

    // ============================================================
    // 4. Обновляем глобальные флаги
    // ============================================================
    config_enabled = temp_config_enabled;

    // struct stat st;
    // if (stat(CONFIG_PATH, &st) == 0) {
    //     config_mtime = st.st_mtime;
    // }

    SYSLOG_INFO("Sync complete: %d entries, %d templates", entry_count, template_count);
    SYSLOG_INFO_D("=== SYNC COMPLETE ===");
    return 0;
}

// ============================================================================
// ПАРСИНГ КОНФИГА ВО ВРЕМЕННЫЙ МАССИВ
// ============================================================================

static int parse_config_to_temp(struct protect_entry **temp_entries, int *temp_count,
                                struct protect_template **temp_templates, int *temp_template_count,
                                int *temp_config_enabled) {


    DEBUG_PRINT("parse_config_to_temp: start");

    // Выделяем память
    *temp_entries = calloc(MAX_PATHS, sizeof(struct protect_entry));
    if (!*temp_entries) {
        SYSLOG_ERR("Failed to allocate memory for temp_entries");
        return -1;
    }

    *temp_templates = calloc(MAX_PATHS, sizeof(struct protect_template));
    if (!*temp_templates) {
        SYSLOG_ERR("Failed to allocate memory for temp_templates");
        free(*temp_entries);
        *temp_entries = NULL;
        return -1;
    }

    time_t new_config_mtime = 0;

    struct stat st;
    if (stat(CONFIG_PATH, &st) == 0) {
        new_config_mtime = st.st_mtime;
    }

    if (access(CONFIG_PATH, R_OK) != 0) {
        SYSLOG_ERR("Config file not accessible: %s (errno=%d)", CONFIG_PATH, errno);
        free(*temp_entries);
        free(*temp_templates);
        *temp_entries = NULL;
        *temp_templates = NULL;
        return -1;
    }

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        SYSLOG_WARN("Config file %s not found", CONFIG_PATH);
        free(*temp_entries);
        free(*temp_templates);
        *temp_entries = NULL;
        *temp_templates = NULL;
        return -1;
    }

    char line[MAX_LINE_LEN];
    int line_num = 0;
    int new_entry_count = 0;
    int new_template_count = 0;
    int new_config_enabled = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        // Удаляем перевод строки в конце
        size_t len = strlen(line);
        if (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[len-1] = '\0';
            if (len > 1 && line[len-2] == '\r') {
                line[len-2] = '\0';
            }
        }

        // Пропускаем пустые строки
        if (line[0] == '\0') continue;

        // Находим начало строки (пропускаем пробелы в начале)
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;

        // Пропускаем комментарии
        if (*start == '#' || *start == '\0') continue;

        // Удаляем пробелы в конце
        char *end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        // Пропускаем пустые строки после обрезки
        if (start[0] == '\0') continue;

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

        if (strncmp(start, "scan_mount", 10) == 0) {
            parse_scan_mount(start);
            continue;
        }

        if (strncmp(start, "protect", 7) == 0) {
            char *ptr = start + 7;
            while (*ptr == ' ' || *ptr == '\t') ptr++;

            if (*ptr == '\0') {
                SYSLOG_WARN("Config line %d: missing path after protect", line_num);
                continue;
            }

            __u64 allowed_inodes[MAX_ALLOWED];
            char allowed_paths[MAX_ALLOWED][MAX_PATH_LEN];
            int allowed_count = 0;
            memset(allowed_inodes, 0, sizeof(allowed_inodes));
            memset(allowed_paths, 0, sizeof(allowed_paths));

            // Парсим путь с поддержкой кавычек
            char raw_path[MAX_PATH_LEN];
            if (parse_quoted_string((const char **)&ptr, raw_path, MAX_PATH_LEN) != 0) {
                SYSLOG_WARN("Config line %d: invalid path", line_num);
                continue;
            }

            // Парсим все программы с поддержкой кавычек
            while (*ptr) {
                char prog_path[PATH_MAX];
                if (parse_quoted_string((const char **)&ptr, prog_path, PATH_MAX) != 0) {
                    break;
                }

                if (prog_path[0] != '\0' && allowed_count < MAX_ALLOWED) {
                    safe_strcpy(allowed_paths[allowed_count], prog_path, MAX_PATH_LEN);

                    // Пытаемся получить inode
                    __u64 allowed_inode = get_inode_from_path(prog_path);
                    allowed_inodes[allowed_count] = allowed_inode;

                    if (allowed_inode != 0) {
                        SYSLOG_INFO("  Allowed program: %s (inode: %lu)", prog_path, (unsigned long)allowed_inode);
                    } else {
                        SYSLOG_WARN("  Allowed program NOT FOUND (will retry): %s", prog_path);
                    }
                    allowed_count++;
                }
            }

            // if (raw_path[0] == '~') {
            struct protect_template *tmpl = &(*temp_templates)[new_template_count];
            safe_strcpy(tmpl->pattern, raw_path, sizeof(tmpl->pattern));
            int isHome = is_home_path(raw_path);

            const char *subpath = raw_path + 1;

            if (isHome) {
                safe_strcpy(tmpl->subpath, subpath, sizeof(tmpl->subpath));
            }

            for (int i = 0; i < allowed_count && i < MAX_ALLOWED; i++) {
                tmpl->allowed_inodes[i] = allowed_inodes[i];
                safe_strcpy(tmpl->allowed_paths[i], allowed_paths[i], MAX_PATH_LEN);
            }
            tmpl->allowed_count = allowed_count;
//                tmpl->enabled = 1;
            tmpl->is_home = isHome;

            if (isHome) {
                SYSLOG_INFO("Config: home template ~%s (will scan all users)", tmpl->subpath);
            }
            else {
                SYSLOG_INFO("Config: path template %s (will scan this path)", tmpl->pattern);
            }

            new_template_count++;

            char *found_paths[MAX_PATHS] = {NULL};  // Инициализируем нулями
            int found_count = 0;

            if (!isHome) {
                // Для не домашнего пути просто используем сам путь
                found_paths[0] = strdup(raw_path);  // или strdup(raw_path)
                if (found_paths[0]) {
                    found_count = 1;
                }
            } else {
                found_count = scan_home_for_template(tmpl->subpath, found_paths, MAX_PATHS);
            }

            for (int i = 0; i < found_count && new_entry_count < MAX_PATHS; i++) {
                struct protect_entry *entry = &(*temp_entries)[new_entry_count];
                safe_strcpy(entry->path, found_paths[i], sizeof(entry->path));
//                SYSLOG_INFO(" ============> %s", entry->path);

                entry->inode = get_inode_from_path(entry->path);
                entry->is_active = (entry->inode != 0);
                entry->allowed_count = 0;
                entry->last_check = time(NULL);
                entry->is_home = isHome;

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
            // } else {
            //     struct protect_entry *entry = &(*temp_entries)[new_entry_count];
            //     safe_strcpy(entry->path, raw_path, sizeof(entry->path));
            //
            //     entry->inode = get_inode_from_path(entry->path);
            //     entry->is_active = (entry->inode != 0);
            //     entry->allowed_count = 0;
            //     entry->last_check = time(NULL);
            //
            //     for (int i = 0; i < allowed_count && i < MAX_ALLOWED; i++) {
            //         entry->allowed_inodes[i] = allowed_inodes[i];
            //         safe_strcpy(entry->allowed_paths[i], allowed_paths[i], MAX_PATH_LEN);
            //         entry->allowed_count++;
            //     }
            //
            //     if (entry->inode != 0) {
            //         SYSLOG_INFO("Config: protect %s (inode: %lu)", entry->path, (unsigned long)entry->inode);
            //     } else {
            //         SYSLOG_WARN("Config: protect %s (NOT FOUND YET, will retry)", entry->path);
            //     }
            //
            //     new_entry_count++;
            // }
        }
    }

    fclose(fp);

    *temp_count = new_entry_count;
    *temp_template_count = new_template_count;
    *temp_config_enabled = new_config_enabled;

    config_mtime = new_config_mtime;

    SYSLOG_INFO("Config parsed to temp: %d entries, %d templates", new_entry_count, new_template_count);
    return 0;
}

// ============================================================================
// ЗАГРУЗКА ОДНОЙ ЗАПИСИ (для новых папок из шаблонов)
// ============================================================================

static int load_single_entry(struct bpf_object *obj, struct protect_entry *entry) {
    if (!entry || entry->inode == 0) return -1;
    return add_folder_to_entries(obj, entry);
}

// ============================================================================
// ПРОВЕРКА НОВЫХ ПАПОК ПО ШАБЛОНАМ
// ============================================================================

static int scan_templates_and_load(struct bpf_object *obj) {
    int found_new = 0;

    SYSLOG_INFO_D("=== SCAN TEMPLATES ===");
    SYSLOG_INFO_D("Templates count: %d", template_count);

    for (int t = 0; t < template_count; t++) {
//        if (!templates[t].enabled) continue;

        char *found_paths[MAX_PATHS] = {NULL};  // Инициализируем нулями
        int found_count = 0;

        if (!templates[t].is_home) {
            // Для не домашнего пути - просто используем сам путь
            SYSLOG_INFO_D("Scanning path template: %s", templates[t].pattern);

            found_paths[0] = strdup(templates[t].pattern);
            if (found_paths[0]) {
                found_count = 1;
            }
        } else {
            SYSLOG_INFO_D("Scanning home template: ~%s", templates[t].subpath);
            found_count = scan_home_for_template(templates[t].subpath, found_paths, MAX_PATHS);
        }

        SYSLOG_INFO_D("Found %d folders for template", found_count);

        for (int i = 0; i < found_count; i++) {
            if (!found_paths[i]) continue;

            int already_exists = 0;
            for (int j = 0; j < entry_count; j++) {
//                SYSLOG_INFO("compare %s and %s", entries[j].path, found_paths[i]);
                if (strcmp(entries[j].path, found_paths[i]) == 0) {
                    already_exists = 1;
                    break;
                }
            }

            if (already_exists) {
                SYSLOG_INFO_D("Folder already exists: %s", found_paths[i]);
                free(found_paths[i]);
                continue;
            }

            if (entry_count < MAX_PATHS) {
                struct protect_entry entry;
                memset(&entry, 0, sizeof(struct protect_entry));
//                SYSLOG_INFO("===> adding %s", found_paths[i]);
                safe_strcpy(entry.path, found_paths[i], sizeof(entry.path));

                entry.inode = get_inode_from_path(entry.path);
                entry.is_active = (entry.inode != 0);
                entry.last_check = time(NULL);
                entry.allowed_count = 0;
                entry.is_home = templates[t].is_home;

                for (int j = 0; j < templates[t].allowed_count && j < MAX_ALLOWED; j++) {
                    entry.allowed_inodes[j] = templates[t].allowed_inodes[j];
                    safe_strcpy(entry.allowed_paths[j], templates[t].allowed_paths[j], MAX_PATH_LEN);
                    entry.allowed_count++;
                }

                if (entry.inode != 0) {
                    SYSLOG_INFO("New folder from template: %s (inode: %lu, programs: %d)",
                                entry.path, (unsigned long)entry.inode, entry.allowed_count);
                    if (load_single_entry(obj, &entry) == 0) {
                        found_new = 1;
                    }
                }

                free(found_paths[i]);
            } else {
                SYSLOG_WARN("Max entries reached, cannot add %s", found_paths[i]);
                free(found_paths[i]);
            }
        }
    }

    SYSLOG_INFO_D("Found new folders: %d", found_new);
    SYSLOG_INFO_D("=== SCAN TEMPLATES COMPLETE ===");
    return found_new;
}

// ============================================================================
// ПРОВЕРКА ИЗМЕНЕНИЯ КОНФИГА
// ============================================================================

static int config_changed(void) {
    struct stat st;
    if (stat(CONFIG_PATH, &st) != 0) return 0;

    if (st.st_mtime != config_mtime) {
//        config_mtime = st.st_mtime;
        return 1;
    }
    return 0;
}

// ============================================================================
// СКАНИРОВАНИЕ ВСЕХ ПРОГРАММ
// ============================================================================

static int scan_all_entries(struct bpf_object *obj) {
    if (!obj) return -1;

    SYSLOG_INFO_D("=== SCANNING ALL ENTRIES ===");
    SYSLOG_INFO_D("Total entries: %d", entry_count);

    int total_removed = 0;
    int total_added = 0;

    for (int i = 0; i < entry_count; i++) {
        if (entries[i].inode == 0) continue;

        SYSLOG_INFO_D("Checking folder: %s (inode: %lu, programs: %d)",
                      entries[i].path,
                      (unsigned long)entries[i].inode,
                      entries[i].allowed_count);

        // Проверяем каждую программу в папке
        for (int j = entries[i].allowed_count - 1; j >= 0; j--) {
            const char *program_path = entries[i].allowed_paths[j];
            __u64 current_inode = get_inode_from_path(program_path);

            if (current_inode == 0 && entries[i].allowed_inodes[j] != 0) {
                // Программа удалена
                SYSLOG_INFO_D("  Program disabling (not found): %s", program_path);
                disable_program_from_ebpf(obj, i, j);

                total_removed++;
            } else if (entries[i].allowed_inodes[j] != current_inode) {
                // Программа пересоздана
                SYSLOG_INFO_D("  Program recreated: %s (old: %lu, new: %lu)",
                              program_path,
                              (unsigned long)entries[i].allowed_inodes[j],
                              (unsigned long)current_inode);
                entries[i].allowed_inodes[j] = current_inode;
                // Обновляем в BPF
                if (obj) {
                    struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
                    if (map) {
                        int fd = bpf_map__fd(map);
                        if (fd >= 0) {
                            struct folder_program_key key = {
                                    .folder_inode = entries[i].inode,
                                    .prog_idx = j
                            };
                            __u64 value = current_inode;
                            bpf_map_update_elem(fd, &key, &value, BPF_ANY);
                            SYSLOG_INFO("Updated program: %s (new inode: %lu)",
                                        program_path, (unsigned long)current_inode);
                            total_added++;
                        }
                    }
                }
            }
        }
    }

    SYSLOG_INFO_D("=== SCAN COMPLETE ===");
    if (total_removed > 0 || total_added > 0) {
        SYSLOG_INFO("Scan complete: %d programs removed, %d programs updated",
                    total_removed, total_added);
    }
    return total_removed + total_added;
}

// ============================================================================
// СКАНИРОВАНИЕ ПОЯВИВШИХСЯ ПРОГРАММ
// ============================================================================

static int scan_missing_programs(struct bpf_object *obj) {
    if (!obj) return -1;

    SYSLOG_INFO_D("=== SCANNING MISSING PROGRAMS ===");

    int found_new = 0;

    for (int i = 0; i < entry_count; i++) {
        if (entries[i].inode == 0) continue;
        if (entries[i].allowed_count == 0) continue;

        SYSLOG_INFO_D("Checking folder: %s", entries[i].path);

        for (int j = 0; j < entries[i].allowed_count; j++) {
            // Если inode == 0, значит программа не была найдена ранее
            if (entries[i].allowed_inodes[j] == 0) {
                const char *program_path = entries[i].allowed_paths[j];
                __u64 current_inode = get_inode_from_path(program_path);

                if (current_inode != 0) {
                    // Программа появилась!
                    SYSLOG_INFO_D("  Program appeared: %s (inode: %lu)",
                                  program_path, (unsigned long)current_inode);

                    // Обновляем inode в entries
                    entries[i].allowed_inodes[j] = current_inode;

                    // Добавляем в BPF
                    struct bpf_map *map = bpf_object__find_map_by_name(obj, "folder_allowed_programs_map");
                    if (map) {
                        int fd = bpf_map__fd(map);
                        if (fd >= 0) {
                            struct folder_program_key key = {
                                    .folder_inode = entries[i].inode,
                                    .prog_idx = j
                            };

                            bpf_map_update_elem(fd, &key, &current_inode, BPF_ANY);
                            SYSLOG_INFO("Program appeared: %s (inode: %lu)",
                                        program_path, (unsigned long)current_inode);
                            found_new++;
                        }
                    }

                    // Обновляем конфигурацию папки
                    map = bpf_object__find_map_by_name(obj, "folder_config_map");
                    if (map) {
                        int fd = bpf_map__fd(map);
                        if (fd >= 0) {
                            struct protected_folder_config config = {
                                    .folder_inode = entries[i].inode,
                                    .allowed_program_count = entries[i].allowed_count,
                            };
                            bpf_map_update_elem(fd, &entries[i].inode, &config, BPF_ANY);
                            SYSLOG_INFO_D("    Folder config updated");
                        }
                    }
                }
            }
        }
    }

    SYSLOG_INFO_D("Found %d new programs", found_new);
    SYSLOG_INFO_D("=== SCAN MISSING PROGRAMS COMPLETE ===");
    return found_new;
}

// ============================================================================
// ИЗМЕНЕНИЕ 3: ФУНКЦИЯ ПОЛНОГО СКАНИРОВАНИЯ (С ОЖИДАНИЕМ МЬЮТЕКСА)
// ============================================================================
static void perform_full_scan(struct bpf_object *obj) {
    if (!obj) return;

    // Захватываем мьютекс с ожиданием в очереди
    SYSLOG_INFO_D("Full scan: waiting for mutex...");
    pthread_mutex_lock(&scan_mutex);
    SYSLOG_INFO_D("Full scan: mutex acquired");

    SYSLOG_INFO_D("Starting full scan from templates...");

    int changed = 0;

    // Сканируем шаблоны и загружаем новые папки
    if (scan_templates_and_load(obj)) {
        changed = 1;
    }

    // Проверяем программы в существующих папках
    if (scan_all_entries(obj) > 0) {
        changed = 1;
    }

    // Проверяем пропавшие программы
    if (scan_missing_programs(obj) > 0) {
        changed = 1;
    }

    if (changed) {
        SYSLOG_INFO("Full scan completed, changes detected");
    } else {
        SYSLOG_INFO_D("Full scan completed, no changes");
    }

    SYSLOG_INFO_D("Full scan: releasing mutex");
    pthread_mutex_unlock(&scan_mutex);
}
// ============================================================================

// ============================================================================
// ИЗМЕНЕНИЕ 3: ОБРАБОТЧИК СИГНАЛА ДЛЯ ПРИНУДИТЕЛЬНОГО СКАНИРОВАНИЯ
// ============================================================================
static volatile int signal_scan_requested = 0;

static void signal_handler_scan(int sig) {
    if (sig == SIGUSR1) {
        SYSLOG_INFO("Received SIGUSR1 signal, full scan requested");
        signal_scan_requested = 1;
    }
}
// ============================================================================

// ============================================================================
// ФУНКЦИЯ ПОИСКА BPF ОБЪЕКТА
// ============================================================================

static const char* find_bpf_object(void) {
    static char path[PATH_MAX];
    struct stat st;

    const char *paths[] = {
            "/usr/local/lib/app_data_sec/app_data_sec.bpf.o",
            "./app_data_sec.bpf.o",
//        "../app_data_sec.bpf.o",
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
// ПРОВЕРКА АВТОКОНФИГУРАЦИИ
// ============================================================================

static int autoconfig_changed(void) {
    struct stat st;
    time_t current_mtime = 0;
    time_t saved_timestamp = 0;

    // Проверяем существование директории
    if (stat(AUTOCONFIG_DIR, &st) != 0) {
        SYSLOG_INFO_D("Auto-config directory not found: %s", AUTOCONFIG_DIR);
        return 0;
    }

    // Получаем текущее время изменения директории
    current_mtime = st.st_mtime;

    // Проверяем, есть ли .conf файлы в директории
    DIR *dir = opendir(AUTOCONFIG_DIR);
    if (!dir) {
        SYSLOG_INFO_D("Cannot open auto-config directory: %s", AUTOCONFIG_DIR);
        return 0;
    }

    int has_conf = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char *ext = strrchr(entry->d_name, '.');
        if (ext && strcmp(ext, ".conf") == 0) {
            has_conf = 1;
            break;
        }
    }
    closedir(dir);

    if (!has_conf) {
        SYSLOG_INFO_D("No .conf files in auto-config directory");
        return 0;
    }

    // Читаем сохранённое время
    FILE *fp = fopen(AUTOCONFIG_TIMESTAMP, "r");
    if (fp) {
        if (fscanf(fp, "%ld", &saved_timestamp) == 1) {
            SYSLOG_INFO_D("Saved timestamp: %ld, current: %ld", saved_timestamp, current_mtime);
        }
        fclose(fp);
    }

    // Если время изменилось или файл с временем не существует
    if (current_mtime != saved_timestamp) {
        // Сохраняем новое время
        fp = fopen(AUTOCONFIG_TIMESTAMP, "w");
        if (fp) {
            fprintf(fp, "%ld", current_mtime);
            fclose(fp);
            SYSLOG_INFO("Auto-config timestamp updated: %ld", current_mtime);
        }
        return 1;
    }

    return 0;
}

static int apply_autoconfig(void) {
    SYSLOG_INFO("Auto-config changed! Applying new configurations...");

    // Проверяем наличие merge_config
    const char *merge_config_paths[] = {
            "/usr/local/bin/app_data_sec_merge_config",
            "/usr/bin/app_data_sec_merge_config",
            "./app_data_sec_merge_config",
            NULL
    };

    char merge_cmd[PATH_MAX];
    int found = 0;

    for (int i = 0; merge_config_paths[i] != NULL; i++) {
        if (access(merge_config_paths[i], X_OK) == 0) {
            strcpy(merge_cmd, merge_config_paths[i]);
            found = 1;
            break;
        }
    }

    if (!found) {
        SYSLOG_ERR("app_data_sec_merge_config not found, cannot apply auto-config");
        return -1;
    }

    // Формируем команду
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "%s --autoconfig", merge_cmd);

    SYSLOG_INFO("Running: %s", cmd);

    int result = system(cmd);
    if (result != 0) {
        SYSLOG_ERR("Failed to apply auto-config (exit code: %d)", result);
        return -1;
    }

    SYSLOG_INFO("Auto-config applied successfully");
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
    fprintf(stderr, "\n");
    fprintf(stderr, "Configuration directives in %s:\n", CONFIG_PATH);
    fprintf(stderr, "  enable = yes|no          Enable/disable protection\n");
    fprintf(stderr, "  protect <path> [prog...] Protect folder, allow programs\n");
    fprintf(stderr, "  scan_mount <path>        Scan templates when path appears/mounted\n");
    fprintf(stderr, "  Quotes \"path with spaces\" Support spaces in paths\n");
}

// ============================================================================
// ПРОВЕРКА БЛОКИРОВКИ ПОВТОРНОГО ЗАПУСКА
// ============================================================================

static int check_single_instance(void) {
    int fd;
    char pid_str[32];
    pid_t existing_pid = 0;

    // Открываем PID-файл
    fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        SYSLOG_ERR("Failed to open PID file %s: %s", PID_FILE, strerror(errno));
        return 0;
    }

    // Пытаемся захватить блокировку
    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        // Блокировка уже захвачена - читаем PID
        FILE *fp = fopen(PID_FILE, "r");
        if (fp) {
            if (fscanf(fp, "%d", &existing_pid) == 1) {
                if (kill(existing_pid, 0) == 0) {
                    SYSLOG_ERR("Another instance is already running (PID: %d). Exiting.", existing_pid);
                    fclose(fp);
                    close(fd);
                    return 0;  // ВОЗВРАЩАЕМ 0 - ПРОЦЕСС ЖИВ
                } else {
                    SYSLOG_WARN("PID file exists but process %d is dead. Overriding...", existing_pid);
                }
            }
            fclose(fp);
        }

        // Процесс мёртв - перезаписываем файл
        close(fd);
        fd = open(PID_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            SYSLOG_ERR("Failed to recreate PID file: %s", strerror(errno));
            return 0;
        }

        if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
            SYSLOG_ERR("Failed to lock PID file after recreate: %s", strerror(errno));
            close(fd);
            return 0;
        }
    }

    // Записываем наш PID в файл
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(fd, 0) == -1) {
        SYSLOG_WARN("Failed to truncate PID file: %s", strerror(errno));
    }
    if (write(fd, pid_str, strlen(pid_str)) < 0) {
        SYSLOG_WARN("Failed to write PID to %s: %s", PID_FILE, strerror(errno));
    }

    SYSLOG_INFO("PID file created: %s (PID: %d)", PID_FILE, getpid());
    return 1;
}

// Функция для удаления PID-файла при корректном завершении
static void remove_pid_file(void) {
    unlink(PID_FILE);
    SYSLOG_INFO("PID file removed: %s", PID_FILE);
    fflush(stdout);
}

// Обработчик сигналов
static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        SYSLOG_INFO("Received signal %d, shutting down...", sig);
        keep_running = 0;
    }
}

// ============================================================================
// ФУНКЦИЯ ПРОВЕРКИ, ЧТО ПАПКА НЕ ПУСТА
// ============================================================================

static int is_directory_not_empty(const char *path) {
    if (!path || path[0] == '\0') return 0;

    DIR *dir = opendir(path);
    if (!dir) return 0;

    struct dirent *entry;
    int has_files = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        has_files = 1;
        break;
    }
    closedir(dir);

    return has_files;
}

// ============================================================================
// ПАРСИНГ ДИРЕКТИВЫ SCAN_MOUNT
// ============================================================================

static int parse_scan_mount(const char *line) {
    if (!line) return -1;

    char *ptr = (char *)line + strlen("scan_mount");
    while (*ptr == ' ' || *ptr == '\t') ptr++;

    if (*ptr == '\0') {
        SYSLOG_WARN("Missing path after scan_mount");
        return -1;
    }

    char raw_path[MAX_PATH_LEN];
    if (parse_quoted_string((const char **)&ptr, raw_path, MAX_PATH_LEN) != 0) {
        SYSLOG_WARN("Invalid scan_mount path");
        return -1;
    }

    if (raw_path[0] == '\0') {
        SYSLOG_WARN("Empty scan_mount path");
        return -1;
    }

    // Проверяем, не добавлен ли уже этот путь
    for (int i = 0; i < scan_mount_path_count; i++) {
        if (strcmp(scan_mount_paths[i].path, raw_path) == 0) {
            SYSLOG_INFO_D("scan_mount path already added: %s", raw_path);
            return 0;
        }
    }

    if (scan_mount_path_count >= MAX_SCAN_MOUNT_PATHS) {
        SYSLOG_WARN("Max scan_mount paths reached");
        return -1;
    }

    // Сохраняем исходный шаблон
    safe_strcpy(scan_mount_paths[scan_mount_path_count].original_pattern, raw_path, MAX_PATH_LEN);

    // Определяем, является ли путь домашним
    scan_mount_paths[scan_mount_path_count].is_home = is_home_path(raw_path);

    if (scan_mount_paths[scan_mount_path_count].is_home) {
        // Для ~ пути сохраняем подпуть
        safe_strcpy(scan_mount_paths[scan_mount_path_count].subpath, raw_path + 1, MAX_PATH_LEN);
        // Для отображения в логах используем raw_path
//        SYSLOG_INFO("====> Added scan_mount path ~");
        safe_strcpy(scan_mount_paths[scan_mount_path_count].path, raw_path, MAX_PATH_LEN);
        SYSLOG_INFO("Added scan_mount path: %s (home template)", raw_path);
    } else {
        // Для обычных путей - пытаемся расширить ~
//        char expanded_path[MAX_PATH_LEN];
//        if (expand_home_path(raw_path, expanded_path, sizeof(expanded_path)) == 0) {
//            safe_strcpy(scan_mount_paths[scan_mount_path_count].path, expanded_path, MAX_PATH_LEN);
//            SYSLOG_INFO("Added scan_mount path: %s (expanded to: %s)", raw_path, expanded_path);
//        } else {
//        SYSLOG_INFO("====> Added scan_mount path =");
            safe_strcpy(scan_mount_paths[scan_mount_path_count].path, raw_path, MAX_PATH_LEN);
            SYSLOG_INFO("Added scan_mount path: %s", raw_path);
//        }
    }

    scan_mount_paths[scan_mount_path_count].is_mounted = is_directory_not_empty(scan_mount_paths[scan_mount_path_count].path);
    scan_mount_paths[scan_mount_path_count].last_check = time(NULL);

    SYSLOG_INFO("  Currently %s", scan_mount_paths[scan_mount_path_count].is_mounted ? "mounted" : "not mounted");

    scan_mount_path_count++;
    return 0;
}

// ============================================================================
// ПРОВЕРКА ВСЕХ SCAN_MOUNT ПУТЕЙ
// ============================================================================

static int check_scan_mount_paths(void) {
    if (scan_mount_path_count == 0) {
        return 0;
    }

    int mount_changed = 0;

    for (int i = 0; i < scan_mount_path_count; i++) {
        // Проверяем, не пуста ли папка (это означает, что она смонтирована)
        int not_empty = is_directory_not_empty(scan_mount_paths[i].path);

        // Считаем монтирование валидным только если папка смонтирована И не пуста
        int is_valid_mount = not_empty;

        if (is_valid_mount != scan_mount_paths[i].is_mounted) {
            if (is_valid_mount) {
                SYSLOG_INFO("scan_mount: valid mount detected: %s (mounted and not empty)",
                            scan_mount_paths[i].path);
            } else {
                SYSLOG_INFO("scan_mount: path unmounted: %s", scan_mount_paths[i].path);
            }
            scan_mount_paths[i].is_mounted = is_valid_mount;
            scan_mount_paths[i].last_check = time(NULL);
            mount_changed = 1;
        }
    }

    return mount_changed;
}

// ============================================================================
// ФУНКЦИИ ДЛЯ ОТСЛЕЖИВАНИЯ ПОЛЬЗОВАТЕЛЕЙ
// ============================================================================

static int is_home_user_processed(const char *username) {
    if (!username || username[0] == '\0') return 0;

    for (int i = 0; i < processed_home_users_count; i++) {
        if (strcmp(processed_home_users[i], username) == 0) {
            return 1;
        }
    }
    return 0;
}

static void add_processed_home_user(const char *username) {
    if (!username || username[0] == '\0') return;
    if (processed_home_users_count >= MAX_HOME_USERS) return;
    if (is_home_user_processed(username)) return;

    safe_strcpy(processed_home_users[processed_home_users_count], username, MAX_PATH_LEN);
    processed_home_users_count++;
    SYSLOG_INFO_D("Added processed home user: %s (total: %d)", username, processed_home_users_count);
}

//static void clear_processed_home_users(void) {
//    memset(processed_home_users, 0, sizeof(processed_home_users));
//    processed_home_users_count = 0;
//    SYSLOG_INFO_D("Cleared processed home users list");
//}

// ============================================================================
// ФУНКЦИЯ УДАЛЕНИЯ НЕСУЩЕСТВУЮЩИХ ПОЛЬЗОВАТЕЛЕЙ ИЗ СПИСКА
// ============================================================================

static void remove_processed_home_users(void) {
    int removed_count = 0;
    int i = 0;

    while (i < processed_home_users_count) {
        char *full_path = processed_home_users[i];
//        snprintf(full_path, sizeof(full_path), "%s", processed_home_users[i]);

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISDIR(st.st_mode) || !is_directory_not_empty(full_path)) {
            // Директория пользователя больше не смонтирована - удаляем из списка
            SYSLOG_INFO_D("Home directory no longer exists, removing from processed list: %s",
                          processed_home_users[i]);

            // Сдвигаем все элементы влево
            for (int j = i; j < processed_home_users_count - 1; j++) {
                safe_strcpy(processed_home_users[j], processed_home_users[j + 1], MAX_PATH_LEN);
            }
            processed_home_users_count--;
            removed_count++;
            // Не увеличиваем i, так как на место удаленного встал следующий элемент
        } else {
            i++;
        }
    }

    if (removed_count > 0) {
        SYSLOG_INFO("Removed %d non-existing home users from processed list, remaining: %d",
                      removed_count, processed_home_users_count);
    }
}

// ============================================================================
// ФУНКЦИЯ ПРОВЕРКИ НОВЫХ ДОМАШНИХ ДИРЕКТОРИЙ
// ============================================================================

static int check_new_home_directories(struct bpf_object *obj, int without_rescan) {
    if (!obj) return 0;

    int found_new = 0;
    DIR *dir = opendir(HOME_PATH);
    if (!dir) {
        SYSLOG_WARN_D("Cannot open home directory: %s", HOME_PATH);
        return 0;
    }

    struct dirent *entry;
    struct stat st;

    // Сканируем HOME_PATH и собираем все существующие директории

    SYSLOG_INFO_D("Scanning %s for existing directories...", HOME_PATH);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s%s", HOME_PATH, entry->d_name);

        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode) && is_directory_not_empty(full_path)) {
            int is_processed = is_home_user_processed(full_path);
            if (!found_new && !is_processed) {
                SYSLOG_INFO("New home directory, found_new = 1");
                found_new = 1;
//                strcpy(new_username, full_path);
            } else {
                SYSLOG_INFO_D("Home user already processed: %s", full_path);
            }

            if (!is_processed) {
                SYSLOG_INFO("New home directory detected (not processed), added: %s", full_path);
                add_processed_home_user(full_path);
            }
        }

    }
    closedir(dir);

    remove_processed_home_users();

    if (found_new && !without_rescan) {
        SYSLOG_INFO("New home directories detected, running full scan...");
        perform_full_scan(obj);
    }

    return found_new;
}

int main(int argc, char **argv) {
    DEBUG_PRINT("=== MAIN START ===");

    struct bpf_program *prog;
    struct bpf_map *map;
    struct bpf_object *bpf_obj = NULL;
    int err = 0;
    int log_level = 1;
    const char *bpf_file = NULL;

    // Проверяем, не запущен ли уже другой экземпляр
    openlog("app_data_sec_loader", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    // ПРОВЕРКА БЛОКИРОВКИ - САМАЯ ПЕРВАЯ
    if (!check_single_instance()) {
        SYSLOG_ERR("Another instance is already running. Exiting.");
        closelog();
        return 1;
    }

    // Устанавливаем обработчики сигналов
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    // ============================================================================
    // ИЗМЕНЕНИЕ 3: УСТАНАВЛИВАЕМ ОБРАБОТЧИК SIGUSR1
    // ============================================================================
    signal(SIGUSR1, signal_handler_scan);

    // Регистрируем удаление PID-файла при выходе
    atexit(remove_pid_file);

    DEBUG_PRINT("sizeof(protect_entry) = %zu bytes", sizeof(struct protect_entry));
    DEBUG_PRINT("sizeof(protect_template) = %zu bytes", sizeof(struct protect_template));
    DEBUG_PRINT("entries array (%d): %zu KB\n", MAX_PATHS, (sizeof(entries) / 1024));
    DEBUG_PRINT("templates array (%d): %zu KB\n", MAX_PATHS, (sizeof(templates) / 1024));
    DEBUG_PRINT("Total: %zu KB (%.2f MB)\n",
                (sizeof(entries) + sizeof(templates)) / 1024,
                (double)(sizeof(entries) + sizeof(templates)) / (1024 * 1024));

    SYSLOG_INFO("APP DATA SEC LOADER STARTING (PID: %d)", getpid());
    SYSLOG_INFO("APP DATA SEC LOADER v%s (built: %s)", VERSION, VERSION_DATE);

    DEBUG_PRINT("Parsing command line arguments...");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 < argc) {
                log_level = atoi(argv[i + 1]);
                if (log_level < 0 || log_level > 2) {
                    SYSLOG_ERR("Invalid log_level: %d", log_level);
                    print_usage(argv[0]);
                    closelog();
                    return 1;
                }
                i++;
            } else {
                SYSLOG_ERR("--log-level requires a value");
                print_usage(argv[0]);
                closelog();
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            closelog();
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            return 0;
        }
        else {
            SYSLOG_ERR("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            closelog();
            return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (UID 0)\n");
        fprintf(stderr, "Please use: sudo %s\n", argv[0]);
        return 1;
    }

    int requested_log_level = log_level;

    // Загружаем конфиг во временный массив
    DEBUG_PRINT("Loading config to temp...");
    struct protect_entry *temp_entries = NULL;
    struct protect_template *temp_templates = NULL;

    int temp_count = 0;
    int temp_template_count = 0;
    int temp_config_enabled = 0;

    check_new_home_directories(bpf_obj, 1);

    if (parse_config_to_temp(&temp_entries, &temp_count, &temp_templates, &temp_template_count, &temp_config_enabled) != 0) {
        SYSLOG_ERR("Failed to parse config");
        closelog();
        return 1;
    }

    DEBUG_PRINT("Config loaded: temp_count=%d, temp_template_count=%d, temp_config_enabled=%d",
                temp_count, temp_template_count, temp_config_enabled);

    DEBUG_PRINT("Finding BPF object...");
    bpf_file = find_bpf_object();
    if (!bpf_file) {
        SYSLOG_ERR("BPF object file not found!");
        closelog();
        return 1;
    }
    DEBUG_PRINT("BPF object found: %s", bpf_file);

    DEBUG_PRINT("Opening BPF object...");
    bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(bpf_obj)) {
        SYSLOG_ERR("Failed to open BPF object %s: %s", bpf_file, strerror(-libbpf_get_error(bpf_obj)));
        closelog();
        return 1;
    }
    DEBUG_PRINT("BPF object opened successfully");

    DEBUG_PRINT("Loading BPF object...");
    err = bpf_object__load(bpf_obj);
    if (err) {
        SYSLOG_ERR("Failed to load BPF object: %d", err);
        if (bpf_obj) {
            bpf_object__close(bpf_obj);
        }
        closelog();
        return 1;
    }
    DEBUG_PRINT("BPF object loaded successfully");

    // ТОЛЬКО ПОСЛЕ ЗАГРУЗКИ BPF инициализируем entries из temp
    DEBUG_PRINT("Initializing entries from temp...");
    memset(entries, 0, sizeof(entries));
    entry_count = 0;

//    Это не нужно, иначе не добавляются папки в ebpf
//    for (int i = 0; i < temp_count; i++) {
//        memcpy(&entries[i], &temp_entries[i], sizeof(struct protect_entry));
//    }
//    entry_count = temp_count;

    memset(templates, 0, sizeof(templates));
    template_count = 0;

    //    Это не нужно, иначе не добавляются папки в ebpf
//    memcpy(templates, temp_templates, sizeof(struct protect_template) * temp_template_count);
//    template_count = temp_template_count;
//    config_enabled = temp_config_enabled;

    // Синхронизируем entries с BPF
    DEBUG_PRINT("Syncing entries to BPF...");
    sync_config_to_entries(
            bpf_obj,
            temp_entries,
            temp_count,
            temp_templates,
            temp_template_count,
            temp_config_enabled
    );
    DEBUG_PRINT("Sync complete");

    // Освобождаем временную память
    free(temp_entries);
    free(temp_templates);
    temp_entries = NULL;
    temp_templates = NULL;

    // struct stat st;
    // if (stat(CONFIG_PATH, &st) == 0) {
    //     config_mtime = st.st_mtime;
    // }

    // Прикрепляем LSM-программы
    DEBUG_PRINT("Attaching LSM programs...");
    bpf_object__for_each_program(prog, bpf_obj) {
        const char *name = bpf_program__name(prog);
        if (strncmp(name, "block_", 6) != 0) continue;

        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (link) {
            SYSLOG_INFO("Attached: %s", name);
        } else {
            SYSLOG_ERR("Failed to attach: %s", name);
        }
    }
    DEBUG_PRINT("LSM programs attached");

    // Устанавливаем уровень логирования
    DEBUG_PRINT("Setting log level...");
    map = bpf_object__find_map_by_name(bpf_obj, "log_level_map");
    if (map) {
        int fd = bpf_map__fd(map);
        if (fd >= 0) {
            __u32 key = 0;
            __u32 log_level_val = requested_log_level;
            bpf_map_update_elem(fd, &key, &log_level_val, BPF_ANY);
            DEBUG_PRINT("Log level set to %d", requested_log_level);
        }
    }

    SYSLOG_INFO("eBPF LSM programs attached. %d entries loaded, %d templates",
                entry_count, template_count);
    SYSLOG_INFO("Log level: %d (0=off, 1=blocked only, 2=everything)", requested_log_level);
    SYSLOG_INFO("Auto-reload enabled: config check every %d seconds, new folders every %d seconds",
                CHECK_INTERVAL, RETRY_INTERVAL);
    SYSLOG_INFO("Config file: %s", CONFIG_PATH);

    time_t last_folder_check = time(NULL);
    time_t last_autoconfig_check = time(NULL) - AUTOCONFIG_CHECK_INTERVAL - 100;

    SYSLOG_INFO("Entering main loop...");

    while (keep_running) {
        time_t now = time(NULL);

        // ============================================================================
        // ИЗМЕНЕНИЕ 3: ПРОВЕРКА СИГНАЛА ДЛЯ ПРИНУДИТЕЛЬНОГО СКАНИРОВАНИЯ
        // ============================================================================
        if (signal_scan_requested) {
            signal_scan_requested = 0;
            SYSLOG_INFO("Processing forced scan request from signal");
            perform_full_scan(bpf_obj);
        }

        now = time(NULL);
        if (!keep_running) break;

        // Проверка автоконфигурации (раз в час)
        if (keep_running && (now - last_autoconfig_check >= AUTOCONFIG_CHECK_INTERVAL)) {
            if (autoconfig_changed()) {
                SYSLOG_INFO("Auto-config directory changed, applying...");

                // Применяем автоконфигурацию
                if (apply_autoconfig() == 0) {
                    // После применения автоконфига, перезагружаем основную конфигурацию
                    SYSLOG_INFO("Will be reloading configuration after auto-config update...");
                }
            }
            last_autoconfig_check = now;
        }

        now = time(NULL);
        if (!keep_running) break;

        // ============================================================================
        // ПРОВЕРКА появления новых директорий в папке home
        // ============================================================================
        static time_t last_home_scan = 0;
        if (now - last_home_scan >= HOME_SCAN_INTERVAL) {
            check_new_home_directories(bpf_obj, 0);
            last_home_scan = now;
        }

        if (!keep_running) break;

        // Проверяем завершение с задержкой 500 мс
        usleep(500000);

        now = time(NULL);
        if (!keep_running) break;

        // ============================================================================
        // ПРОВЕРКА SCAN_MOUNT ПУТЕЙ
        // ============================================================================
        static time_t last_scan_mount_check = 0;
        if (now - last_scan_mount_check >= MOUNT_CHECK_INTERVAL) {
            if (check_scan_mount_paths()) {
                SYSLOG_INFO("scan_mount: mount change detected, running full scan...");
                perform_full_scan(bpf_obj);
            }
            last_scan_mount_check = now;
        }

        now = time(NULL);
        if (!keep_running) break;

        // Проверка изменений конфига
        if (config_changed()) {
            SYSLOG_INFO_D("Config change: waiting for sync mutex...");
            pthread_mutex_lock(&scan_mutex);
            SYSLOG_INFO_D("Config change: mutex acquired");

            SYSLOG_INFO("Config changed! Reloading...");

            struct protect_entry *new_temp_entries = NULL;
            struct protect_template *new_temp_templates = NULL;
            int new_temp_count = 0;
            int new_temp_template_count = 0;
            int new_temp_config_enabled = 0;

            if (parse_config_to_temp(&new_temp_entries, &new_temp_count,
                                     &new_temp_templates, &new_temp_template_count,
                                     &new_temp_config_enabled) != 0) {
                SYSLOG_ERR("Failed to parse config after change");
                pthread_mutex_unlock(&scan_mutex);
                continue;
            }

            sync_config_to_entries(
                    bpf_obj,
                    new_temp_entries,
                    new_temp_count,
                    new_temp_templates,
                    new_temp_template_count,
                    new_temp_config_enabled
            );

            // Освобождаем временную память
            free(new_temp_entries);
            free(new_temp_templates);
            new_temp_entries = NULL;
            new_temp_templates = NULL;

            // struct stat st;
            // if (stat(CONFIG_PATH, &st) == 0) {
            //     config_mtime = st.st_mtime;
            // }

            last_folder_check = now;

            SYSLOG_INFO_D("Config change: releasing mutex");
            pthread_mutex_unlock(&scan_mutex);
        }

        if (now - last_folder_check >= RETRY_INTERVAL) {
            // ============================================================================
            // ИЗМЕНЕНИЕ 2: ИСПОЛЬЗУЕМ perform_full_scan() ВМЕСТО РАЗРОЗНЕННЫХ СКАНИРОВАНИЙ
            // ============================================================================
            perform_full_scan(bpf_obj);
            last_folder_check = now;
        }
    }

    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }

    SYSLOG_INFO("APP DATA SEC LOADER EXITING");
    closelog();
    DEBUG_PRINT("=== MAIN EXIT ===");
    return err;
}