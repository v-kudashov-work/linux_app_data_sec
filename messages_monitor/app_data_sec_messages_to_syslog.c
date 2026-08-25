// app_data_sec_messages_to_syslog.c - с полной информацией о директории (многострочный вывод)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <termios.h>
#include <sys/select.h>

#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define BUFFER_SIZE 8192
#define MAX_PID_LEN 16
#define MAX_MSG_LEN 8192
#define MAX_PROCESS_CHAIN 32
#define MAX_PATH_LEN 4096
#define MAX_TABLE_ROWS 1000
#define MAX_OPERATIONS 256

// Структура для хранения информации о процессе
typedef struct {
    pid_t pid;
    char exe_path[PATH_MAX];
    char cmdline[PATH_MAX];
    char comm[64];
} process_info_t;

// Структура для хранения информации о директории
typedef struct {
    unsigned long long inode;
    char path[PATH_MAX];
    char name[PATH_MAX];
    char parent_path[PATH_MAX];
    uid_t uid;
    gid_t gid;
    char owner[256];
    char group[256];
    mode_t mode;
    char permissions[11];
    off_t size;
    time_t mtime;
    char mtime_str[64];
    int is_directory;
    int is_protected;
    unsigned long long protected_inode;
    char protected_path[PATH_MAX];
} dir_info_t;

// Структура для хранения строки таблицы
typedef struct {
    char timestamp[64];
    char folder_path[PATH_MAX];
    char process_tree[2048];
    char operations[2048];
    unsigned long long inode;
    pid_t pid;
    time_t last_update;
    bool active;
    int entry_num;
} table_row_t;

// Глобальные переменные для таблицы
static table_row_t table[MAX_TABLE_ROWS];
static int table_count = 0;
static bool terminal_mode = false;
static struct termios orig_termios;
static int pipe_fd = -1;
static int entry_counter = 0;
static bool redraw_needed = true;

// Безопасная функция копирования строки
static void safe_strncpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) return;
    size_t src_len = strnlen(src, size - 1);
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
}

// Функция для получения пути по inode (рекурсивный поиск)
static int find_path_by_inode_recursive(const char *base_path, unsigned long long target_inode, char *found_path, int depth) {
    if (depth > 20) return 0;

    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char full_path[MAX_PATH_LEN];

    dir = opendir(base_path);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);

        if (lstat(full_path, &st) == 0) {
            if (st.st_ino == target_inode) {
                safe_strncpy(found_path, full_path, MAX_PATH_LEN);
                closedir(dir);
                return 1;
            }

            if (S_ISDIR(st.st_mode)) {
                if (find_path_by_inode_recursive(full_path, target_inode, found_path, depth + 1)) {
                    closedir(dir);
                    return 1;
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

// Функция для получения пути по inode
static char* get_path_by_inode(unsigned long long inode) {
    static char path[MAX_PATH_LEN];
    path[0] = '\0';

    if (find_path_by_inode_recursive("/", inode, path, 0)) {
        return path;
    }

    if (find_path_by_inode_recursive("/home", inode, path, 0)) {
        return path;
    }

    if (find_path_by_inode_recursive("/opt", inode, path, 0)) {
        return path;
    }

    if (find_path_by_inode_recursive("/var", inode, path, 0)) {
        return path;
    }

    snprintf(path, sizeof(path), "unknown (inode: %llu)", inode);
    return path;
}

// Функция для получения имени владельца по UID
static char* get_owner_name(uid_t uid) {
    static char name[256];
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        snprintf(name, sizeof(name), "%s (UID:%d)", pw->pw_name, uid);
    } else {
        snprintf(name, sizeof(name), "UID:%d", uid);
    }
    return name;
}

// Функция для получения имени группы по GID
static char* get_group_name(gid_t gid) {
    static char name[256];
    struct group *gr = getgrgid(gid);
    if (gr) {
        snprintf(name, sizeof(name), "%s (GID:%d)", gr->gr_name, gid);
    } else {
        snprintf(name, sizeof(name), "GID:%d", gid);
    }
    return name;
}

// Функция для получения прав доступа
static void get_permissions(mode_t mode, char *perm) {
    perm[0] = S_ISDIR(mode) ? 'd' : '-';
    perm[1] = (mode & S_IRUSR) ? 'r' : '-';
    perm[2] = (mode & S_IWUSR) ? 'w' : '-';
    perm[3] = (mode & S_IXUSR) ? 'x' : '-';
    perm[4] = (mode & S_IRGRP) ? 'r' : '-';
    perm[5] = (mode & S_IWGRP) ? 'w' : '-';
    perm[6] = (mode & S_IXGRP) ? 'x' : '-';
    perm[7] = (mode & S_IROTH) ? 'r' : '-';
    perm[8] = (mode & S_IWOTH) ? 'w' : '-';
    perm[9] = (mode & S_IXOTH) ? 'x' : '-';
    perm[10] = '\0';
}

// Функция для форматирования времени
static void format_time(time_t t, char *buf, size_t size) {
    struct tm *tm_info = localtime(&t);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Функция для получения информации о директории по inode
static dir_info_t get_directory_info(unsigned long long inode) {
    dir_info_t info;
    memset(&info, 0, sizeof(info));

    info.inode = inode;
    info.uid = -1;
    info.gid = -1;

    if (inode == 0) {
        safe_strncpy(info.path, "unknown", sizeof(info.path));
        return info;
    }

    char *path = get_path_by_inode(inode);
    if (path) {
        safe_strncpy(info.path, path, sizeof(info.path));
    }

    struct stat st;
    if (stat(info.path, &st) == 0) {
        info.uid = st.st_uid;
        info.gid = st.st_gid;
        info.mode = st.st_mode;
        info.size = st.st_size;
        info.mtime = st.st_mtime;
        info.is_directory = S_ISDIR(st.st_mode);

        safe_strncpy(info.owner, get_owner_name(st.st_uid), sizeof(info.owner));
        safe_strncpy(info.group, get_group_name(st.st_gid), sizeof(info.group));
        get_permissions(st.st_mode, info.permissions);
        format_time(st.st_mtime, info.mtime_str, sizeof(info.mtime_str));

        char *last_slash = strrchr(info.path, '/');
        if (last_slash) {
            safe_strncpy(info.name, last_slash + 1, sizeof(info.name));
        } else {
            safe_strncpy(info.name, info.path, sizeof(info.name));
        }

        if (last_slash && last_slash > info.path) {
            size_t parent_len = last_slash - info.path;
            if (parent_len > 0 && parent_len < sizeof(info.parent_path)) {
                safe_strncpy(info.parent_path, info.path, parent_len + 1);
            } else {
                safe_strncpy(info.parent_path, "/", sizeof(info.parent_path));
            }
        } else {
            safe_strncpy(info.parent_path, "/", sizeof(info.parent_path));
        }
    } else {
        snprintf(info.path, sizeof(info.path), "not_found (inode: %llu)", inode);
        safe_strncpy(info.name, "not_found", sizeof(info.name));
    }

    return info;
}

// Функция для получения пути к исполняемому файлу по PID
static char* get_process_path(pid_t pid) {
    static char path[PATH_MAX];
    char proc_path[64];
    ssize_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    len = readlink(proc_path, path, sizeof(path) - 1);
    if (len < 0) {
        safe_strncpy(path, "unknown", sizeof(path));
        return path;
    }

    path[len] = '\0';

    char *deleted = strstr(path, " (deleted)");
    if (deleted) {
        *deleted = '\0';
    }

    return path;
}

// Функция для получения командной строки процесса по PID
static char* get_process_cmdline(pid_t pid) {
    static char cmdline[PATH_MAX];
    char proc_path[64];
    FILE *fp;
    size_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        safe_strncpy(cmdline, "unknown", sizeof(cmdline));
        return cmdline;
    }

    len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    if (len == 0) {
        safe_strncpy(cmdline, "empty", sizeof(cmdline));
        return cmdline;
    }

    for (size_t i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    cmdline[len] = '\0';

    while (len > 0 && cmdline[len - 1] == ' ') {
        cmdline[len - 1] = '\0';
        len--;
    }

    return cmdline;
}

// Функция для получения имени процесса (comm)
static char* get_process_comm(pid_t pid) {
    static char comm[64];
    char proc_path[64];
    FILE *fp;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        safe_strncpy(comm, "unknown", sizeof(comm));
        return comm;
    }

    if (fgets(comm, sizeof(comm), fp) == NULL) {
        safe_strncpy(comm, "unknown", sizeof(comm));
    } else {
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n') {
            comm[len-1] = '\0';
        }
    }

    fclose(fp);
    return comm;
}

// Функция для получения информации о процессе
static bool get_process_info(pid_t pid, process_info_t *info) {
    if (!info || pid <= 0) {
        return false;
    }

    info->pid = pid;

    // Получаем путь к исполняемому файлу
    char *exe_path = get_process_path(pid);
    if (exe_path) {
        strncpy(info->exe_path, exe_path, PATH_MAX - 1);
        info->exe_path[PATH_MAX - 1] = '\0';
    } else {
        snprintf(info->exe_path, sizeof(info->exe_path), "unknown");
    }

    // Получаем командную строку
    char *cmdline = get_process_cmdline(pid);
    if (cmdline) {
        strncpy(info->cmdline, cmdline, PATH_MAX - 1);
        info->cmdline[PATH_MAX - 1] = '\0';
    } else {
        snprintf(info->cmdline, sizeof(info->cmdline), "unknown");
    }

    // Получаем имя процесса
    char *comm = get_process_comm(pid);
    if (comm) {
        strncpy(info->comm, comm, sizeof(info->comm) - 1);
        info->comm[sizeof(info->comm) - 1] = '\0';
    } else {
        snprintf(info->comm, sizeof(info->comm), "unknown");
    }

    return true;
}

// Функция для получения PID родительского процесса из /proc
static pid_t get_parent_pid_from_proc(pid_t pid) {
    char proc_path[64];
    FILE *fp;
    pid_t ppid = -1;
    char buffer[1024];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", pid);

    fp = fopen(proc_path, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strncmp(buffer, "PPid:", 5) == 0) {
            sscanf(buffer + 5, "%d", &ppid);
            break;
        }
    }

    fclose(fp);
    return ppid;
}

// Функция для проверки существования процесса
static bool process_exists(pid_t pid) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    return access(proc_path, F_OK) == 0;
}

// Функция для сбора цепочки процессов
static int collect_process_chain_v2(pid_t pid, process_info_t *chain, int max_depth) {
    if (!chain || max_depth <= 0 || pid <= 0) {
        return 0;
    }

    int depth = 0;
    pid_t current_pid = pid;
    pid_t prev_pid = 0;
    int max_iterations = max_depth * 2;

    // Проверяем, существует ли процесс
    if (!process_exists(pid)) {
        return 0;
    }

    while (current_pid > 0 && depth < max_depth && max_iterations > 0) {
        max_iterations--;

        // Проверяем, существует ли процесс
        if (!process_exists(current_pid)) {
            break;
        }

        // Получаем информацию о процессе
        if (!get_process_info(current_pid, &chain[depth])) {
            pid_t next_pid = get_parent_pid_from_proc(current_pid);
            if (next_pid > 0 && next_pid != current_pid) {
                current_pid = next_pid;
                continue;
            }
            break;
        }

        depth++;

        // Получаем родительский PID
        prev_pid = current_pid;
        current_pid = get_parent_pid_from_proc(current_pid);

        // Проверяем на ошибки
        if (current_pid == prev_pid || current_pid < 0) {
            break;
        }

        // Если достигли init (PID 1)
        if (current_pid == 1) {
            if (depth < max_depth && process_exists(1)) {
                if (get_process_info(1, &chain[depth])) {
                    depth++;
                }
            }
            break;
        }

        // Если текущий PID стал меньше 1
        if (current_pid < 1) {
            break;
        }
    }

    // Если цепочка пустая, но процесс существует
    if (depth == 0 && pid > 0 && process_exists(pid)) {
        if (get_process_info(pid, &chain[0])) {
            depth = 1;
        }
    }

    return depth;
}

// Функция для форматирования цепочки процессов в строку с иерархией
static void format_process_tree(process_info_t *chain, int depth, char *output, size_t output_size) {
    int pos = 0;

    for (int i = depth - 1; i >= 0; i--) {
        if (pos >= output_size - 1) break;

        // Добавляем отступы для иерархии
        for (int j = 0; j < (depth - 1 - i) * 2; j++) {
            if (pos >= output_size - 1) break;
            output[pos++] = ' ';
        }

        if (i < depth - 1) {
            if (pos < output_size - 1) output[pos++] = '|';
            if (pos < output_size - 1) output[pos++] = '-';
        }

        int written = snprintf(output + pos, output_size - pos,
                               "%s (PID:%d, EXE:%s)",
                               chain[i].comm[0] != '\0' ? chain[i].comm : "unknown",
                               chain[i].pid,
                               chain[i].exe_path);
        if (written < 0) break;
        pos += written;

        if (i > 0 && pos < output_size - 1) {
            output[pos++] = '\n';
        }
    }
    output[pos] = '\0';
}

// Функция для парсинга PID из строки лога
static pid_t extract_pid(const char *line) {
    const char *pid_str = NULL;
    const char *p = line;

    // Ищем BLOCKED_PID= или PID=
    while (*p) {
        if (strncmp(p, "BLOCKED_PID=", 12) == 0) {
            pid_str = p + 12;
            break;
        }
        if (strncmp(p, "PID=", 4) == 0) {
            pid_str = p + 4;
            break;
        }
        p++;
    }

    if (!pid_str) {
        return -1;
    }

    pid_t pid = 0;
    while (*pid_str && isdigit(*pid_str)) {
        pid = pid * 10 + (*pid_str - '0');
        pid_str++;
    }

    return pid;
}

// Функция для извлечения inode директории из строки лога
static unsigned long long extract_folder_inode(const char *line) {
    const char *inode_str = NULL;
    const char *p = line;

    while (*p) {
        if (strncmp(p, "FOLDER_INODE=", 13) == 0) {
            inode_str = p + 13;
            break;
        }
        p++;
    }

    if (!inode_str) {
        return 0;
    }

    unsigned long long inode = 0;
    while (*inode_str && isdigit(*inode_str)) {
        inode = inode * 10 + (*inode_str - '0');
        inode_str++;
    }

    return inode;
}

// Функция для извлечения операции из строки лога
static void extract_operation(const char *line, char *operation, size_t size) {
    const char *op_start = NULL;
    const char *p = line;

    // Ищем операцию после APP_DATA_SEC:
    const char *app_data = strstr(line, "APP_DATA_SEC:");
    if (app_data) {
        p = app_data + 13;
        // Пропускаем пробелы
        while (*p == ' ') p++;
        // Извлекаем первую часть до пробела
        char *end = strchr(p, ' ');
        if (end) {
            size_t len = end - p;
            if (len < size - 1) {
                safe_strncpy(operation, p, len + 1);
                return;
            }
        } else {
            safe_strncpy(operation, p, size);
            return;
        }
    }

    // Ищем OPERATION=
    p = line;
    while (*p) {
        if (strncmp(p, "OPERATION=", 10) == 0) {
            op_start = p + 10;
            break;
        }
        p++;
    }

    if (!op_start) {
        safe_strncpy(operation, "unknown", size);
        return;
    }

    char *op_end = strchr(op_start, ' ');
    if (op_end) {
        size_t len = op_end - op_start;
        if (len < size - 1) {
            safe_strncpy(operation, op_start, len + 1);
        } else {
            safe_strncpy(operation, op_start, size);
        }
    } else {
        safe_strncpy(operation, op_start, size);
    }
}

// Функция для извлечения временной метки из строки лога
static void extract_timestamp(const char *line, char *timestamp, size_t size) {
    // Пытаемся найти формат "день.месяц.год час:мин:сек" или "YYYY-MM-DD HH:MM:SS"
    const char *p = line;

    // Ищем формат "DD.MM.YYYY HH:MM:SS" (из syslog)
    while (*p) {
        if (isdigit(p[0]) && isdigit(p[1]) && p[2] == '.' &&
            isdigit(p[3]) && isdigit(p[4]) && p[5] == '.' &&
            isdigit(p[6]) && isdigit(p[7]) && isdigit(p[8]) && isdigit(p[9]) &&
            p[10] == ' ') {
            // Нашли формат "DD.MM.YYYY HH:MM:SS"
            const char *end = p + 19; // "DD.MM.YYYY HH:MM:SS"
            if (end[0] && (end[0] == ' ' || end[0] == '\0' || end[0] == ':' || end[0] == '.')) {
                size_t len = 19;
                if (len < size - 1) {
                    safe_strncpy(timestamp, p, len + 1);
                    return;
                }
            }
        }
        // Ищем формат "YYYY-MM-DD HH:MM:SS"
        if (isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && isdigit(p[3]) &&
            p[4] == '-' && isdigit(p[5]) && isdigit(p[6]) && p[7] == '-' &&
            isdigit(p[8]) && isdigit(p[9]) && p[10] == ' ') {
            const char *end = p + 19; // "YYYY-MM-DD HH:MM:SS"
            if (end[0] && (end[0] == ' ' || end[0] == '\0' || end[0] == ':' || end[0] == '.')) {
                size_t len = 19;
                if (len < size - 1) {
                    safe_strncpy(timestamp, p, len + 1);
                    return;
                }
            }
        }
        p++;
    }

    // Если не нашли, используем текущее время
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Функция для обновления или добавления строки в таблицу
static void update_table(const char *line, const char *folder_path, const char *process_tree,
                         const char *operation, unsigned long long inode, pid_t pid, time_t now) {
    char timestamp[64];
    extract_timestamp(line, timestamp, sizeof(timestamp));

    // Ищем существующую запись с такой же папкой и процессом
    int found = -1;
    for (int i = 0; i < table_count; i++) {
        if (table[i].inode == inode &&
            strcmp(table[i].folder_path, folder_path) == 0 &&
            strcmp(table[i].process_tree, process_tree) == 0 &&
            table[i].active) {
            found = i;
            break;
        }
    }

    if (found >= 0) {
        // Обновляем существующую запись
        if (table[found].last_update < now) {
            safe_strncpy(table[found].timestamp, timestamp, sizeof(table[found].timestamp));
            table[found].last_update = now;
        }

        // Проверяем, есть ли уже такая операция
        char *ops = table[found].operations;
        if (strstr(ops, operation) == NULL) {
            if (strlen(ops) + strlen(operation) + 3 < sizeof(table[found].operations)) {
                if (strlen(ops) > 0) {
                    strcat(ops, ", ");
                }
                strcat(ops, operation);
            }
        }
    } else if (table_count < MAX_TABLE_ROWS) {
        // Добавляем новую запись
        safe_strncpy(table[table_count].timestamp, timestamp, sizeof(table[table_count].timestamp));
        safe_strncpy(table[table_count].folder_path, folder_path, sizeof(table[table_count].folder_path));
        safe_strncpy(table[table_count].process_tree, process_tree, sizeof(table[table_count].process_tree));
        safe_strncpy(table[table_count].operations, operation, sizeof(table[table_count].operations));
        table[table_count].inode = inode;
        table[table_count].pid = pid;
        table[table_count].last_update = now;
        table[table_count].active = true;
        table[table_count].entry_num = ++entry_counter;
        table_count++;
    }
    redraw_needed = true;
}

// Функция для очистки таблицы
static void clear_table() {
    memset(table, 0, sizeof(table));
    table_count = 0;
    entry_counter = 0;
    redraw_needed = true;
}

// Функция для копирования таблицы в буфер обмена (Linux)
static void copy_table_to_clipboard() {
    FILE *fp = popen("xclip -selection clipboard 2>/dev/null || xsel -b 2>/dev/null || cat", "w");
    if (!fp) {
        printf("\nClipboard tool not found (install xclip or xsel)\n");
        return;
    }

    for (int i = 0; i < table_count && i < MAX_TABLE_ROWS; i++) {
        if (!table[i].active) continue;

        fprintf(fp, "Entry #%d\n", table[i].entry_num);
        fprintf(fp, "Timestamp: %s\n", table[i].timestamp);
        fprintf(fp, "Folder Full Path: %s\n", table[i].folder_path);
        fprintf(fp, "Process Hierarchy:\n%s\n", table[i].process_tree);
        fprintf(fp, "Operations: %s\n", table[i].operations);
        fprintf(fp, "---------------------------\n");
    }

    int ret = pclose(fp);
    if (ret == 0) {
        printf("\n✅ Table copied to clipboard!\n");
    } else {
        printf("\n❌ Failed to copy to clipboard\n");
    }
}

// Функция для отображения таблицы в многострочном формате
static void display_table() {
    printf("\033[2J\033[H"); // Очищаем экран

    printf("\n📊 APP DATA SEC MONITOR\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n");
    printf("Total entries: %d\n", table_count);
    printf("\n");

    if (table_count == 0) {
        printf("📋 No data in table yet. Waiting for logs...\n");
    } else {
        for (int i = 0; i < table_count && i < MAX_TABLE_ROWS; i++) {
            if (!table[i].active) continue;

            printf("Entry #%d\n", table[i].entry_num);
            printf("Timestamp: %s\n", table[i].timestamp);
            printf("Folder Full Path: %s\n", table[i].folder_path);
            printf("Process Hierarchy:\n%s\n", table[i].process_tree);
            printf("Operations: %s\n", table[i].operations);
            printf("---------------------------\n");
        }
    }

    printf("\nControls: 'c' - Copy, 'r' - Refresh, 'x' - Clear, 'q' - Quit\n");
    redraw_needed = false;
}

// Функция для обработки ввода с клавиатуры
static void handle_input() {
    char ch;
    struct timeval tv;
    fd_set fds;

    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
        if (read(STDIN_FILENO, &ch, 1) > 0) {
            switch (ch) {
                case 'c':
                case 'C':
                    copy_table_to_clipboard();
                    break;
                case 'r':
                case 'R':
                    redraw_needed = true;
                    break;
                case 'x':
                case 'X':
                    clear_table();
                    display_table();
                    break;
                case 'q':
                case 'Q':
                    if (terminal_mode) {
                        printf("\nExiting...\n");
                        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
                        exit(0);
                    }
                    break;
                default:
                    break;
            }
        }
    }
}

// Функция для форматирования информации о директории
static void format_directory_info(unsigned long long inode, char *output, size_t output_size) {
    if (inode == 0) {
        snprintf(output, output_size, "unknown");
        return;
    }

    dir_info_t info = get_directory_info(inode);
    if (info.path[0]) {
        safe_strncpy(output, info.path, output_size);
    } else {
        snprintf(output, output_size, "unknown (inode: %llu)", inode);
    }
}

// Функция для извлечения дерева процессов из строки лога (для PROCESS TREE сообщений)
static void extract_process_tree_from_log(const char *line, char *output, size_t output_size) {
    // Проверяем, есть ли "PROCESS TREE for PID"
    if (strstr(line, "PROCESS TREE for PID") != NULL) {
        // Это сообщение с деревом процессов, копируем его как есть
        safe_strncpy(output, line, output_size);
        return;
    }

    // Ищем EXE= в строке, там может быть цепочка процессов через >
    const char *exe_start = NULL;
    const char *p = line;
    while (*p) {
        if (strncmp(p, "EXE=", 4) == 0) {
            exe_start = p + 4;
            break;
        }
        p++;
    }

    if (exe_start) {
        // Извлекаем до пробела
        char exe_chain[256];
        const char *end = strchr(exe_start, ' ');
        if (end) {
            size_t len = end - exe_start;
            if (len < sizeof(exe_chain) - 1) {
                safe_strncpy(exe_chain, exe_start, len + 1);
            }
        } else {
            safe_strncpy(exe_chain, exe_start, sizeof(exe_chain));
        }

        // Разделяем по > и форматируем как иерархию
        char *token = strtok(exe_chain, ">");
        int level = 0;
        int pos = 0;
        while (token != NULL && pos < output_size - 1) {
            for (int j = 0; j < level * 2 && pos < output_size - 1; j++) {
                output[pos++] = ' ';
            }
            if (level > 0 && pos < output_size - 1) {
                output[pos++] = '|';
                output[pos++] = '-';
            }
            int written = snprintf(output + pos, output_size - pos, "%s\n", token);
            if (written < 0) break;
            pos += written;
            token = strtok(NULL, ">");
            level++;
        }
        output[pos] = '\0';
        return;
    }

    safe_strncpy(output, "No process info", output_size);
}

// Функция для обработки строки лога
static void process_log_line(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
        line[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        return;
    }

    syslog(LOG_INFO, "%s", line);

    // Проверяем, что это PROCESS TREE сообщение
    if (strstr(line, "PROCESS TREE for PID") != NULL) {
        // Отображаем дерево процессов отдельно
        char process_tree[2048];
        safe_strncpy(process_tree, line, sizeof(process_tree));
        // Добавляем в таблицу как специальную запись
        time_t now = time(NULL);
        char timestamp[64];
        extract_timestamp(line, timestamp, sizeof(timestamp));

        // Добавляем в таблицу
        if (table_count < MAX_TABLE_ROWS) {
            safe_strncpy(table[table_count].timestamp, timestamp, sizeof(table[table_count].timestamp));
            safe_strncpy(table[table_count].folder_path, "PROCESS TREE", sizeof(table[table_count].folder_path));
            safe_strncpy(table[table_count].process_tree, process_tree, sizeof(table[table_count].process_tree));
            safe_strncpy(table[table_count].operations, "process_tree", sizeof(table[table_count].operations));
            table[table_count].inode = 0;
            table[table_count].pid = 0;
            table[table_count].last_update = now;
            table[table_count].active = true;
            table[table_count].entry_num = ++entry_counter;
            table_count++;
            redraw_needed = true;
        }
        return;
    }

    // Проверяем, что это наше сообщение
    if (strstr(line, "APP_DATA_SEC:") == NULL) {
        return;
    }

    pid_t pid = extract_pid(line);
    unsigned long long folder_inode = extract_folder_inode(line);

    char operation[256];
    extract_operation(line, operation, sizeof(operation));

    char folder_path[PATH_MAX];
    format_directory_info(folder_inode, folder_path, sizeof(folder_path));

    char process_tree_str[2048] = "";

    if (pid > 0) {
        // Пытаемся собрать цепочку процессов
        process_info_t chain[MAX_PROCESS_CHAIN];
        int depth = collect_process_chain_v2(pid, chain, MAX_PROCESS_CHAIN);

        if (depth > 0) {
            format_process_tree(chain, depth, process_tree_str, sizeof(process_tree_str));
        } else {
            // Если не удалось собрать цепочку, пытаемся извлечь из EXE= поля
            extract_process_tree_from_log(line, process_tree_str, sizeof(process_tree_str));
        }
    } else {
        extract_process_tree_from_log(line, process_tree_str, sizeof(process_tree_str));
    }

    time_t now = time(NULL);
    update_table(line, folder_path, process_tree_str, operation, folder_inode, pid, now);

    if (terminal_mode && redraw_needed) {
        display_table();
    }
}

// Обработчик сигналов
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        if (terminal_mode) {
            tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
        }
        syslog(LOG_INFO, "Application terminated by signal %d", sig);
        closelog();
        exit(0);
    }
}

// Настройка терминала для неблокирующего ввода
static void setup_terminal() {
    struct termios new_termios;
    tcgetattr(STDIN_FILENO, &orig_termios);
    new_termios = orig_termios;
    new_termios.c_lflag &= ~(ICANON | ECHO);
    new_termios.c_cc[VMIN] = 0;
    new_termios.c_cc[VTIME] = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    terminal_mode = true;
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (UID 0)\n");
        fprintf(stderr, "Please use: sudo %s\n", argv[0]);
        return 1;
    }

    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    char line_buffer[BUFFER_SIZE];
    int line_pos = 0;

    // Установка обработчиков сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Открываем системный журнал
    openlog("app_data_sec_messages", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "App Data Sec Messages Reader started");
    syslog(LOG_INFO, "Reading from: %s", TRACE_PIPE);

    // Открываем trace_pipe
    fd = open(TRACE_PIPE, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open %s: %s", TRACE_PIPE, strerror(errno));
        closelog();
        return 1;
    }
    pipe_fd = fd;

    // Настраиваем терминал для интерактивного режима
    setup_terminal();

    printf("\033[2J\033[H");
    printf("\n📊 APP DATA SEC MONITOR\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n");
    printf("Waiting for logs from %s...\n", TRACE_PIPE);
    printf("\nControls: 'c' - Copy, 'r' - Refresh, 'x' - Clear, 'q' - Quit\n\n");
    redraw_needed = true;

    // Основной цикл чтения
    while (1) {
        // Проверяем ввод с клавиатуры
        handle_input();

        // Читаем данные из trace_pipe (неблокирующий режим)
        fd_set read_fds;
        struct timeval tv;

        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        if (select(fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
            bytes_read = read(fd, buffer, sizeof(buffer) - 1);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';

                for (int i = 0; i < bytes_read; i++) {
                    if (buffer[i] == '\n') {
                        line_buffer[line_pos] = '\0';
                        if (line_pos > 0) {
                            process_log_line(line_buffer);
                        }
                        line_pos = 0;
                    } else if (line_pos < sizeof(line_buffer) - 1) {
                        line_buffer[line_pos++] = buffer[i];
                    }
                }
            } else if (bytes_read < 0 && errno != EINTR) {
                syslog(LOG_ERR, "Read error: %s", strerror(errno));
                break;
            }
        }

        // Перерисовываем таблицу если нужно
        if (redraw_needed) {
            display_table();
        }
    }

    close(fd);
    tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
    closelog();
    return 0;
}