// blocker.bpf.c
// 1. Единственный заголовок из системы - vmlinux.h, сгенерированный bpftool
#include "vmlinux.h"

// 2. Все остальные необходимые макросы и определения предоставляет libbpf
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Определение EPERM (Operation not permitted)
#ifndef EPERM
#define EPERM 1
#endif

// Карта для хранения целевого inode
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

// Карта для хранения целевого inode (папка, которую защищаем)
// Карта для хранения целевого inode (папка, которую защищаем)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_inode_map SEC(".maps");

// Карта для хранения inode разрешенной программы
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} allowed_inode_map SEC(".maps");

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
    if (len >= 32) {
        len = 31;
    }

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        name[i] = 0;
        if (i < len) {
            unsigned char c;
            bpf_probe_read_kernel(&c, sizeof(c), &name_ptr[i]);
            name[i] = c;
        }
    }
    name[31] = '\0';
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

// Функция для проверки, является ли inode защищенным
static __always_inline int is_protected_inode(struct dentry *dentry, __u64 *target_inode)
{
    if (!dentry || !target_inode) {
        return 0;
    }

    struct dentry *current = dentry;
    int depth = 0;
    const int MAX_DEPTH = 20;

    #pragma unroll
    for (depth = 0; depth < MAX_DEPTH; depth++) {
        if (!current) {
            break;
        }

        struct inode *inode = NULL;
        bpf_probe_read_kernel(&inode, sizeof(inode), &current->d_inode);

        if (inode) {
            __u64 inode_num = 0;
            bpf_probe_read_kernel(&inode_num, sizeof(inode_num), &inode->i_ino);
            if (inode_num == *target_inode) {
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

// Функция для проверки, является ли процесс или любой из его родителей разрешенным
static __always_inline int is_allowed_process_tree(void)
{
    __u32 key = 0;
    __u64 *allowed_inode = bpf_map_lookup_elem(&allowed_inode_map, &key);
    if (!allowed_inode) {
        return 0;  // Если не задан разрешенный inode - блокируем всех
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    struct task_struct *task = current_task;
    int depth = 0;
    const int MAX_DEPTH = 20;

    #pragma unroll
    for (depth = 0; depth < MAX_DEPTH; depth++) {
        if (!task) {
            break;
        }

        // Проверяем inode текущего процесса
        __u64 inode_num = get_process_exe_inode(task);
        if (inode_num == *allowed_inode) {
            return 1;
        }

        // Поднимаемся к родителю
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

// Функция проверки доступа
static __always_inline int check_access(struct dentry *dentry, const char *operation, int block_self)
{
    __u32 key = 0;
    __u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    if (!dentry) {
        return 0;
    }

    int log_level = get_log_level();

    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    __u64 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    char name[32] = {};
    char parent_name[32] = {};
    get_dentry_name(dentry, name);
    get_parent_name(dentry, parent_name);

    // Проверяем всю цепочку родителей
    int allowed = is_allowed_process_tree();
    int is_self = is_protected_inode(dentry, target_inode);

    struct dentry *parent_dentry = NULL;
    bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);
    int is_inside = 0;
    if (parent_dentry) {
        is_inside = is_protected_inode(parent_dentry, target_inode);
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
        bpf_printk("BLOCKER: %s PID=%llu UID=%llu NAME=%s PARENT=%s ALLOWED=%d BLOCKED=%d REASON=%s COMM=%s\n",
                   operation, pid, uid, name, parent_name, allowed, blocked, reason, comm);
    }

    if (uid == 0) {
        if (log_level >= 2) {
            bpf_printk("BLOCKER: %s ALLOWED ROOT\n", operation);
        }
        return 0;
    }

    if (blocked) {
        if (log_level >= 1) {
            bpf_printk("BLOCKER: %s BLOCKED PID=%llu UID=%llu NAME=%s PARENT=%s REASON=%s COMM=%s\n",
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
