// app_data_sec.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#define MAX_PROTECTED_PATHS 500
#define MAX_ALLOWED_PROGRAMS 10
#define MAX_UNIQUE_SCRIPTS 10
#define MAX_SCRIPTS_PER_FOLDER 3
#define MAX_DEPTH 5
#define MAX_NAME_LEN 32
#define MAX_PATH_LEN 32

// СТРУКТУРЫ ДЛЯ НОВОЙ АРХИТЕКТУРЫ
struct protected_folder_config {
    __u64 folder_inode;          // inode защищенной папки
    __u32 allowed_program_count; // количество разрешенных программ
    __u32 script_count;          // количество разрешенных скриптов
};

// Карта: inode папки -> конфигурация папки
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS);
    __type(key, __u64);                      // inode папки
    __type(value, struct protected_folder_config); // конфигурация
} folder_config_map SEC(".maps");

// Карта: inode папки + индекс -> inode разрешенной программы
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS * MAX_ALLOWED_PROGRAMS);
    __type(key, __u64);   // (folder_inode << 32) | index
    __type(value, __u64); // inode программы
} folder_allowed_programs_map SEC(".maps");

// Карта: inode папки + индекс скрипта -> путь к скрипту
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS * MAX_SCRIPTS_PER_FOLDER);
    __type(key, __u64);   // (folder_inode << 32) | script_index
    __type(value, char[MAX_PATH_LEN]); // путь к скрипту
} folder_scripts_map SEC(".maps");

// Карта для контроля включения проверки скриптов (глобально)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} scripts_enabled_map SEC(".maps");

// Карта для уровня логирования
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} log_level_map SEC(".maps");

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

// Получение имени dentry
static __always_inline void get_dentry_name(struct dentry *dentry, char *name, int size)
{
    if (!dentry) {
        name[0] = '\0';
        return;
    }

    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

    if (!name_ptr) {
        name[0] = '\0';
        return;
    }

    unsigned long len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), &dentry->d_name.len);

    if (len >= size) {
        len = size - 1;
    }

    if (len > 0) {
        bpf_probe_read_kernel(name, len, name_ptr);
    }
    name[len] = '\0';
}

// Получение имени родительской директории
static __always_inline void get_parent_name(struct dentry *dentry, char *name, int size)
{
    name[0] = '\0';
    if (!dentry) {
        return;
    }

    struct dentry *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
    if (!parent) {
        return;
    }

    get_dentry_name(parent, name, size);
}

// Получение inode процесса
static __always_inline __u64 get_process_exe_inode(struct task_struct *task)
{
    if (!task) {
        return 0;
    }

    struct mm_struct *mm = NULL;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (!mm) {
        return 0;
    }

    struct file *exe_file = NULL;
    bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file);
    if (!exe_file) {
        return 0;
    }

    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &exe_file->f_inode);
    if (!inode) {
        return 0;
    }

    __u64 inode_num = 0;
    bpf_probe_read_kernel(&inode_num, sizeof(inode_num), &inode->i_ino);
    return inode_num;
}

// Получение родительского процесса
static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    if (!task) {
        return NULL;
    }

    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    return parent;
}

// Проверка, является ли процесс разрешенным для конкретной папки
static __always_inline int is_allowed_for_folder(struct task_struct *task, __u64 folder_inode)
{
    if (!task || folder_inode == 0) {
        return 0;
    }

    // Получаем конфигурацию папки
    struct protected_folder_config *config = bpf_map_lookup_elem(&folder_config_map, &folder_inode);
    if (!config) {
        return 0;
    }

    // Проверяем все уровни процесса (сам процесс + родители)
    struct task_struct *current_task = task;

    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!current_task) {
            break;
        }

        __u64 exe_inode = get_process_exe_inode(current_task);
        if (exe_inode == 0) {
            current_task = get_parent_task(current_task);
            continue;
        }

        // Проверяем, есть ли этот inode в списке разрешенных для папки
        int found = 0;
        for (int i = 0; i < config->allowed_program_count && i < MAX_ALLOWED_PROGRAMS; i++) {
            __u64 key = (folder_inode << 32) | i;
            __u64 *allowed_inode = bpf_map_lookup_elem(&folder_allowed_programs_map, &key);
            if (allowed_inode && *allowed_inode == exe_inode) {
                found = 1;
                break;
            }
        }

        if (found) {
            return 1;
        }

        current_task = get_parent_task(current_task);
    }

    return 0;
}

// Проверка скрипта в командной строке для конкретной папки
static __always_inline int is_script_allowed_for_folder(const char *cmdline, __u64 folder_inode)
{
    if (!cmdline || cmdline[0] == '\0' || folder_inode == 0) {
        return 0;
    }

    // Получаем конфигурацию папки
    struct protected_folder_config *config = bpf_map_lookup_elem(&folder_config_map, &folder_inode);
    if (!config || config->script_count == 0) {
        return 0;
    }

    // Находим начало пути к скрипту (после пробела)
    int start = 0;
    int found_space = 0;

    for (int i = 0; i < MAX_PATH_LEN - 1 && cmdline[i] != '\0'; i++) {
        if (cmdline[i] == ' ') {
            start = i + 1;
            found_space = 1;
            break;
        }
    }

    if (!found_space) {
        return 0;
    }

    // Проверяем все скрипты для этой папки
    for (int i = 0; i < config->script_count && i < MAX_SCRIPTS_PER_FOLDER; i++) {
        __u64 key = (folder_inode << 32) | i;
        char *script_path = bpf_map_lookup_elem(&folder_scripts_map, &key);
        if (!script_path) {
            continue;
        }

        // Сравниваем script_path с cmdline начиная с позиции start
        int match = 1;
        for (int j = 0; j < MAX_PATH_LEN - 1; j++) {
            if (script_path[j] == '\0') {
                if (cmdline[start + j] == '\0' || cmdline[start + j] == ' ') {
                    match = 1;
                } else {
                    match = 0;
                }
                break;
            }
            if (cmdline[start + j] != script_path[j]) {
                match = 0;
                break;
            }
            if (cmdline[start + j] == '\0') {
                match = 0;
                break;
            }
        }

        if (match) {
            return 1;
        }
    }

    return 0;
}

// Проверка дерева процессов для конкретной папки (учитывая скрипты)
static __always_inline int is_allowed_process_tree_for_folder(__u64 folder_inode)
{
    if (folder_inode == 0) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // Проверяем, включена ли проверка скриптов
    __u32 key = 0;
    __u32 *scripts_enabled = bpf_map_lookup_elem(&scripts_enabled_map, &key);
    int check_scripts = (scripts_enabled && *scripts_enabled == 1);

    // Определяем, является ли текущий процесс шеллом
    int is_shell = (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h');

    struct task_struct *task = current_task;

    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!task) {
            break;
        }

        // Проверка по inode программы
        if (is_allowed_for_folder(task, folder_inode)) {
            return 1;
        }

        // Проверка скриптов (только если это shell и скрипты включены)
        if (check_scripts && is_shell) {
            struct mm_struct *mm = NULL;
            bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
            if (mm) {
                unsigned long *arg_start = NULL;
                bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start);
                if (arg_start) {
                    char cmdline[MAX_PATH_LEN] = {};
                    bpf_probe_read_str(cmdline, sizeof(cmdline), (void *)arg_start);

                    if (cmdline[0] != '\0' && is_script_allowed_for_folder(cmdline, folder_inode)) {
                        return 1;
                    }
                }
            }
        }

        task = get_parent_task(task);
    }

    return 0;
}

// Проверка, является ли inode защищенным (возвращает inode защищенной папки)
static __always_inline __u64 get_protected_folder_inode(struct dentry *dentry)
{
    if (!dentry) {
        return 0;
    }

    struct dentry *current = dentry;

    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!current) {
            break;
        }

        struct inode *inode = NULL;
        bpf_probe_read_kernel(&inode, sizeof(inode), &current->d_inode);

        if (inode) {
            __u64 inode_num = 0;
            bpf_probe_read_kernel(&inode_num, sizeof(inode_num), &inode->i_ino);

            // Проверяем, есть ли этот inode в карте конфигураций
            struct protected_folder_config *config = bpf_map_lookup_elem(&folder_config_map, &inode_num);
            if (config) {
                return inode_num;
            }
        }

        struct dentry *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &current->d_parent);
        if (!parent || parent == current) {
            break;
        }
        current = parent;
    }

    return 0;
}

// Получение уровня логирования
static __always_inline int get_log_level(void)
{
    __u32 key = 0;
    __u32 *level = bpf_map_lookup_elem(&log_level_map, &key);
    if (!level) {
        return 0;
    }
    return *level;
}

// ОСНОВНАЯ ФУНКЦИЯ ПРОВЕРКИ ДОСТУПА (ОПТИМИЗИРОВАННАЯ)
static __always_inline int check_access(struct dentry *dentry, const char *operation, int block_self)
{
    if (!dentry) {
        return 0;
    }

    int log_level = get_log_level();

    // 1. САМАЯ ПЕРВАЯ ПРОВЕРКА: root всегда разрешен
    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    if (uid == 0) {
        if (log_level >= 2) {
            __u64 pid = bpf_get_current_pid_tgid() >> 32;
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s ROOT_ALLOWED PID=%llu PATH=%s\n", operation, pid, name);
        }
        return 0;
    }

    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // 2. ПРОВЕРЯЕМ: является ли путь защищенным
    __u64 folder_inode = get_protected_folder_inode(dentry);
    int is_protected = (folder_inode != 0);

    if (!is_protected) {
        // Путь не защищен - разрешаем доступ
        if (log_level >= 2) {
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s PID=%llu UID=%llu PATH=%s NOT_PROTECTED - ALLOWED\n",
                       operation, pid, uid, name);
        }
        return 0;
    }

    // 3. ПУТЬ ЗАЩИЩЕН - проверяем разрешенные процессы для ЭТОЙ папки
    int allowed = is_allowed_process_tree_for_folder(folder_inode);

    // 4. Если процесс разрешен - доступ разрешен всегда
    if (allowed) {
        if (log_level >= 2) {
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s ALLOWED PID=%llu UID=%llu PATH=%s REASON=allowed_process\n",
                       operation, pid, uid, name);
        }
        return 0;
    }

    // 5. Процесс НЕ разрешен - применяем политику block_self
    int blocked = 0;
    const char *reason = "";

    if (block_self == 1) {
        // block_self=1: блокируем ВСЁ (и саму папку, и содержимое)
        blocked = 1;
        reason = "block_all";
    } else {
        // block_self=0: блокируем только содержимое, разрешаем доступ к самой папке
        // Определяем, является ли запрашиваемый путь САМОЙ защищенной папкой
        __u64 current_inode = 0;
        struct inode *inode = NULL;
        bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
        if (inode) {
            bpf_probe_read_kernel(&current_inode, sizeof(current_inode), &inode->i_ino);
        }

        int is_folder_itself = (current_inode == folder_inode);

        if (is_folder_itself) {
            blocked = 0;
            reason = "folder_itself_allowed";
        } else {
            blocked = 1;
            reason = "content_blocked";
        }
    }

    // Логирование и возврат результата
    if (blocked) {
        if (log_level >= 1) {
            char name[MAX_NAME_LEN] = {};
            char parent_name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            get_parent_name(dentry, parent_name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s BLOCKED PID=%llu UID=%llu PATH=%s PARENT=%s FOLDER_INODE=%llu REASON=%s COMM=%s\n",
                       operation, pid, uid, name, parent_name, folder_inode, reason, comm);
        }
        return -EPERM;
    } else {
        if (log_level >= 2) {
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s ALLOWED PID=%llu UID=%llu PATH=%s REASON=%s\n",
                       operation, pid, uid, name, reason);
        }
        return 0;
    }
}

// ============ ХУКИ ============

SEC("lsm/inode_getattr")
int BPF_PROG(block_inode_getattr, const struct path *path)
{
    if (!path || !path->dentry) {
        return 0;
    }
    return check_access(path->dentry, "GETATTR", 0);
}

SEC("lsm/file_open")
int BPF_PROG(block_file_open, struct file *file)
{
    if (!file || !file->f_path.dentry) {
        return 0;
    }
    return check_access(file->f_path.dentry, "OPEN", 1);
}

SEC("lsm/path_unlink")
int BPF_PROG(block_path_unlink, const struct path *dir, struct dentry *dentry)
{
    return check_access(dentry, "UNLINK", 1);
}

SEC("lsm/path_rmdir")
int BPF_PROG(block_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    return check_access(dentry, "RMDIR", 1);
}

SEC("lsm/path_mkdir")
int BPF_PROG(block_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dir->dentry, "MKDIR", 0);
}

SEC("lsm/path_rename")
int BPF_PROG(block_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    int ret = check_access(old_dentry, "RENAME_OLD", 1);
    if (ret != 0) {
        return ret;
    }
    return check_access(new_dentry, "RENAME_NEW", 1);
}

SEC("lsm/inode_create")
int BPF_PROG(block_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dentry->d_parent, "INODE_CREATE", 1);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(block_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dentry->d_parent, "INODE_MKDIR", 1);
}

char LICENSE[] SEC("license") = "GPL";
