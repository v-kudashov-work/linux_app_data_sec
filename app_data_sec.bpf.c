// app_data_sec.bpf.c - С ИСПОЛЬЗОВАНИЕМ bpf_probe_read_kernel_str
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
    __u64 folder_inode;
    __u32 allowed_program_count;
    __u32 script_count;
};

// Карта: inode папки -> конфигурация папки
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS);
    __type(key, __u64);
    __type(value, struct protected_folder_config);
} folder_config_map SEC(".maps");

// Карта: inode папки + индекс -> inode разрешенной программы
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS * MAX_ALLOWED_PROGRAMS);
    __type(key, __u64);
    __type(value, __u64);
} folder_allowed_programs_map SEC(".maps");

// Карта: inode папки + индекс скрипта -> путь к скрипту
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS * MAX_SCRIPTS_PER_FOLDER);
    __type(key, __u64);
    __type(value, char[MAX_PATH_LEN]);
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

// Получение имени dentry (ИСПРАВЛЕНА - использует bpf_probe_read_kernel_str)
static __always_inline void get_dentry_name(struct dentry *dentry, char *name, int size)
{
    if (!dentry || !name || size <= 0) {
        if (name && size > 0) {
            name[0] = '\0';
        }
        return;
    }

    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

    if (!name_ptr) {
        name[0] = '\0';
        return;
    }

    // bpf_probe_read_kernel_str безопасен для верификатора
    // и автоматически добавляет нуль-терминатор
    long ret = bpf_probe_read_kernel_str(name, size, name_ptr);

    if (ret <= 0) {
        name[0] = '\0';
    }
}

// Получение имени родительской директории
static __always_inline void get_parent_name(struct dentry *dentry, char *name, int size)
{
    if (!dentry || !name || size <= 0) {
        if (name && size > 0) {
            name[0] = '\0';
        }
        return;
    }

    struct dentry *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
    if (!parent) {
        name[0] = '\0';
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

    struct protected_folder_config *config = bpf_map_lookup_elem(&folder_config_map, &folder_inode);
    if (!config) {
        return 0;
    }

    struct task_struct *current_task = task;

    #pragma unroll
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!current_task) {
            break;
        }

        __u64 exe_inode = get_process_exe_inode(current_task);
        if (exe_inode == 0) {
            current_task = get_parent_task(current_task);
            continue;
        }

        int found = 0;
        #pragma unroll
        for (int i = 0; i < MAX_ALLOWED_PROGRAMS; i++) {
            if (i >= config->allowed_program_count) {
                break;
            }
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

// Проверка скрипта в командной строке (ИСПРАВЛЕНА)
static __always_inline int is_script_path_in_cmdline(const char *cmdline, const char *script_path)
{
    if (!cmdline || !script_path) {
        return 0;
    }

    char cmdline_copy[MAX_PATH_LEN] = {};
    char script_copy[MAX_PATH_LEN] = {};

    // Безопасно копируем строки в локальные буферы
    long ret1 = bpf_probe_read_kernel_str(cmdline_copy, sizeof(cmdline_copy), cmdline);
    long ret2 = bpf_probe_read_kernel_str(script_copy, sizeof(script_copy), script_path);

    if (ret1 <= 0 || ret2 <= 0) {
        return 0;
    }

    // Находим начало пути к скрипту (первый пробел после /bin/bash)
    int start = 0;
    int found_space = 0;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
        if (cmdline_copy[i] == '\0') break;
        if (cmdline_copy[i] == ' ') {
            start = i + 1;
            found_space = 1;
            break;
        }
    }

    if (!found_space) {
        return 0;
    }

    // Сравниваем строки
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
        if (script_copy[i] == '\0') {
            if (cmdline_copy[start + i] == '\0' || cmdline_copy[start + i] == ' ') {
                return 1;
            }
            return 0;
        }
        if (cmdline_copy[start + i] != script_copy[i]) {
            return 0;
        }
        if (cmdline_copy[start + i] == '\0') {
            return 0;
        }
    }

    return 0;
}

// Проверка скрипта для конкретной папки (ИСПРАВЛЕНА)
static __always_inline int is_script_allowed_for_folder(const char *cmdline, __u64 folder_inode)
{
    if (!cmdline || folder_inode == 0) {
        return 0;
    }

    struct protected_folder_config *config = bpf_map_lookup_elem(&folder_config_map, &folder_inode);
    if (!config || config->script_count == 0) {
        return 0;
    }

    //TODO может быть упростить и не копировать
    char cmdline_copy[MAX_PATH_LEN] = {};
    long ret = bpf_probe_read_kernel_str(cmdline_copy, sizeof(cmdline_copy), cmdline);
    if (ret <= 0) {
        return 0;
    }

    // Находим начало пути к скрипту (после пробела)
    int start = 0;
    int found_space = 0;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
        if (cmdline_copy[i] == '\0') break;
        if (cmdline_copy[i] == ' ') {
            start = i + 1;
            found_space = 1;
            break;
        }
    }

    if (!found_space) {
        return 0;
    }

    #pragma unroll
    for (int i = 0; i < MAX_SCRIPTS_PER_FOLDER; i++) {
        if (i >= config->script_count) {
            break;
        }

        __u64 key = (folder_inode << 32) | i;
        char *script_path = bpf_map_lookup_elem(&folder_scripts_map, &key);
        if (!script_path) {
            continue;
        }

        //TODO может быть упростить и не копировать
        
        char script_copy[MAX_PATH_LEN] = {};
        long ret2 = bpf_probe_read_kernel_str(script_copy, sizeof(script_copy), script_path);
        if (ret2 <= 0) {
            continue;
        }

        int match = 1;
        #pragma unroll
        for (int j = 0; j < MAX_PATH_LEN - 1; j++) {
            if (script_copy[j] == '\0') {
                if (cmdline_copy[start + j] == '\0' || cmdline_copy[start + j] == ' ') {
                    match = 1;
                } else {
                    match = 0;
                }
                break;
            }
            if (cmdline_copy[start + j] != script_copy[j]) {
                match = 0;
                break;
            }
            if (cmdline_copy[start + j] == '\0') {
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

// Проверка дерева процессов для конкретной папки
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

    __u32 key = 0;
    __u32 *scripts_enabled = bpf_map_lookup_elem(&scripts_enabled_map, &key);
    int check_scripts = (scripts_enabled && *scripts_enabled == 1);

    int is_shell = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (comm[i] == '\0') break;
        if (i == 0 && comm[i] != 'b') break;
        if (i == 1 && comm[i] != 'a') break;
        if (i == 2 && comm[i] != 's') break;
        if (i == 3 && comm[i] == 'h') {
            is_shell = 1;
            break;
        }
    }

    struct task_struct *task = current_task;

    #pragma unroll
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!task) {
            break;
        }

        if (is_allowed_for_folder(task, folder_inode)) {
            return 1;
        }

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

// Проверка, является ли inode защищенным
static __always_inline __u64 get_protected_folder_inode(struct dentry *dentry)
{
    if (!dentry) {
        return 0;
    }

    struct dentry *current = dentry;

    #pragma unroll
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!current) {
            break;
        }

        struct inode *inode = NULL;
        bpf_probe_read_kernel(&inode, sizeof(inode), &current->d_inode);

        if (inode) {
            __u64 inode_num = 0;
            bpf_probe_read_kernel(&inode_num, sizeof(inode_num), &inode->i_ino);

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

// ОСНОВНАЯ ФУНКЦИЯ ПРОВЕРКИ ДОСТУПА
static __always_inline int check_access(struct dentry *dentry, const char *operation, int block_self)
{
    if (!dentry) {
        return 0;
    }

    int log_level = get_log_level();

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

    __u64 folder_inode = get_protected_folder_inode(dentry);
    int is_protected = (folder_inode != 0);

    if (!is_protected) {
        if (log_level >= 2) {
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s PID=%llu UID=%llu PATH=%s NOT_PROTECTED - ALLOWED\n",
                       operation, pid, uid, name);
        }
        return 0;
    }

    int allowed = is_allowed_process_tree_for_folder(folder_inode);

    if (allowed) {
        if (log_level >= 2) {
            char name[MAX_NAME_LEN] = {};
            get_dentry_name(dentry, name, MAX_NAME_LEN);
            bpf_printk("APP_DATA_SEC: %s ALLOWED PID=%llu UID=%llu PATH=%s REASON=allowed_process\n",
                       operation, pid, uid, name);
        }
        return 0;
    }

    int blocked = 0;
    const char *reason = "";

    if (block_self == 1) {
        blocked = 1;
        reason = "block_all";
    } else {
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
