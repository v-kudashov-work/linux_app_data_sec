// app_data_sec_messages_to_syslog.c - с полной информацией о директории (исправленная версия)
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

#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define BUFFER_SIZE 8192
#define MAX_PID_LEN 16
#define MAX_MSG_LEN 8192
#define MAX_PROCESS_CHAIN 32
#define MAX_PATH_LEN 4096

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

// Функция для форматирования цепочки процессов в строку с путями
static void format_process_chain(process_info_t *chain, int depth, char *output, size_t output_size) {
    int pos = 0;

    // Выводим от корня (глубокий) к листу (текущий процесс)
    for (int i = depth - 1; i >= 0; i--) {
        if (pos >= output_size - 1) {
            break;
        }

        // Добавляем информацию о процессе с PID и путем
        int written = snprintf(output + pos, output_size - pos,
                               "[%d] %s (PID:%d, EXE:%s)",
                               depth - i,
                               chain[i].comm[0] != '\0' ? chain[i].comm : "unknown",
                               chain[i].pid,
                               chain[i].exe_path);

        if (written < 0) {
            break;
        }

        pos += written;

        // Добавляем разделитель между процессами
        if (i > 0 && pos < output_size - 1) {
            output[pos++] = ' ';
            output[pos++] = '>';
            output[pos++] = ' ';
        }
    }

    output[pos] = '\0';
}

// Функция для безопасного обрезания строки
static void safe_truncate(char *str, size_t max_len) {
    size_t len = strlen(str);
    if (len >= max_len) {
        str[max_len - 4] = '.';
        str[max_len - 3] = '.';
        str[max_len - 2] = '.';
        str[max_len - 1] = '\0';
    }
}

// Функция для парсинга PID из строки лога
static pid_t extract_pid(const char *line) {
    const char *pid_str = NULL;
    const char *p = line;

    while (*p) {
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

// Функция для форматирования информации о директории (переработанная)
static void format_directory_info(unsigned long long inode, char *output, size_t output_size) {
    if (inode == 0) {
        snprintf(output, output_size, "DIR: unknown");
        return;
    }

    dir_info_t info = get_directory_info(inode);

    // Используем фиксированный размер для каждого поля
    char path_short[128];
    char name_short[64];
    char parent_short[128];

    // Обрезаем длинные строки
    safe_strncpy(path_short, info.path, sizeof(path_short));
    safe_strncpy(name_short, info.name, sizeof(name_short));
    safe_strncpy(parent_short, info.parent_path, sizeof(parent_short));

    // Форматируем с использованием фиксированных размеров
    snprintf(output, output_size,
             "DIR: INODE=%llu PATH=%.120s NAME=%.60s PARENT=%.120s OWNER=%.60s GROUP=%.60s PERMS=%.10s SIZE=%ld MTIME=%.30s IS_DIR=%d",
             info.inode,
             path_short[0] ? path_short : "unknown",
             name_short[0] ? name_short : "unknown",
             parent_short[0] ? parent_short : "unknown",
             info.owner[0] ? info.owner : "unknown",
             info.group[0] ? info.group : "unknown",
             info.permissions[0] ? info.permissions : "unknown",
             (long)info.size,
             info.mtime_str[0] ? info.mtime_str : "unknown",
             info.is_directory);
}

// Функция для обработки строки лога
static void process_log_line(char *line) {
    // Удаляем перевод строки
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
        line[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        return;
    }

    // Проверяем, что это наше сообщение
    if (strstr(line, "APP_DATA_SEC:") == NULL) {
        return;
    }

    syslog(LOG_INFO, "%s", line);

    // Извлекаем PID
    pid_t pid = extract_pid(line);
    unsigned long long folder_inode = extract_folder_inode(line);

    // Формируем сообщение для syslog
    char syslog_msg[MAX_MSG_LEN];
    char chain_str[4096] = "";
    char process_tree[4096] = "";
    char dir_info_str[2048] = "";

    format_directory_info(folder_inode, dir_info_str, sizeof(dir_info_str));

    if (pid > 0) {
        // Собираем цепочку процессов
        process_info_t chain[MAX_PROCESS_CHAIN];
        int depth = collect_process_chain_v2(pid, chain, MAX_PROCESS_CHAIN);

        // Форматируем цепочку с полными путями
        format_process_chain(chain, depth, chain_str, sizeof(chain_str));

        // Формируем дополнительное дерево процессов для наглядности
        int tree_pos = 0;
        for (int i = depth - 1; i >= 0; i--) {
            if (tree_pos >= sizeof(process_tree) - 1) {
                break;
            }

            // Добавляем отступы для иерархии
            for (int j = 0; j < (depth - 1 - i) * 2; j++) {
                if (tree_pos >= sizeof(process_tree) - 1) break;
                process_tree[tree_pos++] = ' ';
            }

            // Добавляем информацию о процессе
            int written = snprintf(process_tree + tree_pos, sizeof(process_tree) - tree_pos,
                                   "|-%s (PID:%d, EXE:%s)\n",
                                   chain[i].comm[0] != '\0' ? chain[i].comm : "unknown",
                                   chain[i].pid,
                                   chain[i].exe_path);

            if (written < 0) break;
            tree_pos += written;
        }
        process_tree[tree_pos] = '\0';

        // Получаем информацию о текущем процессе для дополнительных деталей
        process_info_t current_info;
        if (get_process_info(pid, &current_info)) {
            // Обрезаем слишком длинные строки
            if (strlen(current_info.exe_path) > 256) {
                safe_truncate(current_info.exe_path, 256);
            }
            if (strlen(current_info.cmdline) > 512) {
                safe_truncate(current_info.cmdline, 512);
            }

            // Формируем сообщение с полной информацией
            int written = snprintf(syslog_msg, sizeof(syslog_msg),
                                   "%s | CHAIN: %s | CURRENT: PID=%d EXE=%s CMDLINE=%s | %s",
                                   line, chain_str, pid, current_info.exe_path,
                                   current_info.cmdline, dir_info_str);

            if (written >= (int)sizeof(syslog_msg) - 1) {
                syslog_msg[sizeof(syslog_msg) - 4] = '.';
                syslog_msg[sizeof(syslog_msg) - 3] = '.';
                syslog_msg[sizeof(syslog_msg) - 2] = '.';
                syslog_msg[sizeof(syslog_msg) - 1] = '\0';
            }

            // Дополнительно отправляем дерево процессов отдельным сообщением
            if (depth > 1) {
                syslog(LOG_INFO, "PROCESS TREE for PID %d:\n%s", pid, process_tree);
            }
        } else {
            snprintf(syslog_msg, sizeof(syslog_msg), "%s | CHAIN: %s (PID=%d) | %s",
                     line, chain_str, pid, dir_info_str);
        }

        syslog(LOG_INFO, "%s", syslog_msg);

    } else {
        snprintf(syslog_msg, sizeof(syslog_msg), "%s | %s", line, dir_info_str);
        syslog(LOG_INFO, "%s", syslog_msg);
    }
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

    // Читаем и обрабатываем строки
    while (1) {
        bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';

            // Обрабатываем каждую строку
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

            // Если остались данные без перевода строки
            if (line_pos > 0 && bytes_read > 0 && buffer[bytes_read - 1] != '\n') {
                // Не завершаем строку, ждем продолжения
            }
        } else if (bytes_read < 0) {
            if (errno != EINTR) {
                syslog(LOG_ERR, "Read error: %s", strerror(errno));
                break;
            }
        }
    }

    close(fd);
    closelog();
    return 0;
}