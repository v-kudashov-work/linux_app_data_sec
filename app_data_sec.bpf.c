// app_data_sec.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#define MAX_PROTECTED_PATHS 5000
#define MAX_ALLOWED_PROGRAMS 10
#define MAX_ALLOWED_SCRIPTS 50
#define MAX_DEPTH 20
#define MAX_NAME_LEN 32
#define MAX_PATH_LEN 256

// Карта для хранения целевых inode (HASH)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS);
    __type(key, __u64);
    __type(value, __u8);
} target_inode_map SEC(".maps");

// Карта для хранения разрешенных inode программ (массив)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ALLOWED_PROGRAMS);
    __type(key, __u32);
    __type(value, __u64);
} allowed_inode_map SEC(".maps");

// Карта для хранения разрешенных путей .sh скриптов (массив)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ALLOWED_SCRIPTS);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LEN]);
} allowed_script_path_map SEC(".maps");

// Карта для хранения количества разрешенных .sh скриптов
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} allowed_script_count_map SEC(".maps");

// Карта для хранения количества разрешенных программ (обычных)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} allowed_count_map SEC(".maps");

// Карта для хранения уровня логирования
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} log_level_map SEC(".maps");

// Функция для безопасного копирования имени из dentry
static __always_inline void get_dentry_name(struct dentry *dentry, char *name)
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
    if (len >= MAX_NAME_LEN) {
        len = MAX_NAME_LEN - 1;
    }

    #pragma unroll
    for (int i = 0; i < MAX_NAME_LEN; i++) {
        name[i] = 0;
        if (i < len) {
            unsigned char c;
            bpf_probe_read_kernel(&c, sizeof(c), &name_ptr[i]);
            name[i] = c;
        }
    }
    name[MAX_NAME_LEN - 1] = '\0';
}

// Функция для получения имени родительской директории
static __always_inline void get_parent_name(struct dentry *dentry, char *name)
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

    get_dentry_name(parent, name);
}

// Функция для получения inode исполняемого файла процесса
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

// Функция для получения родительского процесса
static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    if (!task) {
        return NULL;
    }

    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    return parent;
}

// Функция для проверки, содержит ли командная строка разрешенный путь .sh скрипта
static __always_inline int is_script_path_in_cmdline(const char *cmdline, const char *allowed_path)
{
    if (!cmdline || !allowed_path) {
        return 0;
    }

    // Убираем #pragma unroll для этого цикла (он большой)
    for (int pos = 0; pos < MAX_PATH_LEN - 1 && cmdline[pos] != '\0'; pos++) {
        if (cmdline[pos] == allowed_path[0]) {
            int match = 1;
            // Маленький цикл - можно развернуть
            #pragma unroll
            for (int i = 0; i < 32 && allowed_path[i] != '\0'; i++) {
                if (cmdline[pos + i] != allowed_path[i]) {
                    match = 0;
                    break;
                }
                if (allowed_path[i] == '\0') {
                    break;
                }
            }
            if (match) {
                return 1;
            }
        }
    }

    return 0;
}

// Функция для проверки, является ли процесс разрешенным
static __always_inline int is_allowed_process_tree(void)
{
    __u32 count_key = 0;
    __u32 *allowed_count = bpf_map_lookup_elem(&allowed_count_map, &count_key);
    if (!allowed_count || *allowed_count == 0) {
        return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    struct task_struct *task = current_task;

    // Убираем #pragma unroll для большого цикла
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (!task) {
            break;
        }

        // Проверяем inode исполняемого файла
        __u64 inode_num = get_process_exe_inode(task);
        if (inode_num != 0) {
            #pragma unroll
            for (int i = 0; i < MAX_ALLOWED_PROGRAMS; i++) {
                __u32 key = i;
                __u64 *allowed_inode = bpf_map_lookup_elem(&allowed_inode_map, &key);
                if (allowed_inode && *allowed_inode == inode_num) {
                    return 1;
                }
            }
        }

        // Проверяем командную строку (для bash/sh скриптов)
        struct mm_struct *mm = NULL;
        bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
        if (mm) {
            unsigned long *arg_start = NULL;
            unsigned long *arg_end = NULL;
            bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start);
            bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &mm->arg_end);

            if (arg_start && arg_end && arg_start < arg_end) {
                long len = (long)arg_end - (long)arg_start;
                if (len > 0 && len < MAX_PATH_LEN) {
                    char cmdline[MAX_PATH_LEN] = {};
                    bpf_probe_read_str(cmdline, sizeof(cmdline), (void *)arg_start);

                    // Проверяем, является ли процесс bash/sh
                    char comm[16] = {};
                    bpf_get_current_comm(&comm, sizeof(comm));

                    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') {
                        __u32 script_count_key = 0;
                        __u32 *script_count = bpf_map_lookup_elem(&allowed_script_count_map, &script_count_key);

                        if (script_count && *script_count > 0) {
                            // Убираем #pragma unroll для большого цикла
                            for (int i = 0; i < MAX_ALLOWED_SCRIPTS; i++) {
                                __u32 key = i;
                                char *allowed_path = bpf_map_lookup_elem(&allowed_script_path_map, &key);
                                if (allowed_path && is_script_path_in_cmdline(cmdline, allowed_path)) {
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        task = get_parent_task(task);
        if (!task) {
            break;
        }
    }

    return 0;
}

// Функция для получения уровня логирования
static __always_inline int get_log_level(void)
{
    __u32 key = 0;
    __u32 *level = bpf_map_lookup_elem(&log_level_map, &key);
    if (!level) {
        return 0;
    }
    return *level;
}

// Функция для проверки, является ли inode защищенным (HASH - O(1))
static __always_inline int is_protected_inode(struct dentry *dentry)
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

            __u8 *protected = bpf_map_lookup_elem(&target_inode_map, &inode_num);
            if (protected && *protected == 1) {
                return 1;
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

// Функция проверки доступа
static __always_inline int check_access(struct dentry *dentry, const char *operation, int block_self)
{
    if (!dentry) {
        return 0;
    }

    int log_level = get_log_level();

    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    __u64 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    char name[MAX_NAME_LEN] = {};
    char parent_name[MAX_NAME_LEN] = {};
    get_dentry_name(dentry, name);
    get_parent_name(dentry, parent_name);

    int allowed = is_allowed_process_tree();
    int is_self = is_protected_inode(dentry);

    struct dentry *parent_dentry = NULL;
    bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);
    int is_inside = 0;
    if (parent_dentry) {
        is_inside = is_protected_inode(parent_dentry);
    }

    int blocked = 0;
    const char *reason = "";

    if (allowed) {
        blocked = 0;
        reason = "allowed";
    } else if (is_self) {
        if (block_self) {
            blocked = 1;
            reason = "self";
        } else {
            blocked = 0;
            reason = "self_allowed";
        }
    } else if (is_inside) {
        blocked = 1;
        reason = "inside";
    }

    if (log_level >= 2) {
        bpf_printk("APP_DATA_SEC: %s PID=%llu UID=%llu NAME=%s PARENT=%s ALLOWED=%d BLOCKED=%d REASON=%s COMM=%s\n",
                   operation, pid, uid, name, parent_name, allowed, blocked, reason, comm);
    }

    if (uid == 0) {
        if (log_level >= 2) {
            bpf_printk("APP_DATA_SEC: %s ALLOWED ROOT\n", operation);
        }
        return 0;
    }

    if (blocked) {
        if (log_level >= 1) {
            bpf_printk("APP_DATA_SEC: %s BLOCKED PID=%llu UID=%llu NAME=%s PARENT=%s REASON=%s COMM=%s\n",
                       operation, pid, uid, name, parent_name, reason, comm);
        }
        return -EPERM;
    }

    return 0;
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
    return check_access(dir->dentry, "MKDIR", 1);
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
