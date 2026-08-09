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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_inode_map SEC(".maps");

// Карта для хранения уровня логирования
// 0 - без логирования
// 1 - логируем только блокировку
// 2 - логируем всё
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} log_level_map SEC(".maps");

// Вспомогательная функция для логирования с проверкой уровня
static __always_inline void log_event(const char *fmt, ...)
{
    __u32 key = 0;
    __u32 *level = bpf_map_lookup_elem(&log_level_map, &key);
    if (!level || *level == 0) {
        return;
    }

    // Уровень 1 - только блокировки (передаем параметр blocked)
    // Уровень 2 - всё
    // Для простоты используем bpf_printk, но с проверкой уровня в вызывающем коде
}

// Функция для безопасного копирования имени из dentry
static __always_inline void get_dentry_name(struct dentry *dentry, char *name)
{
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        name[i] = 0;
    }

    if (!dentry) {
        return;
    }

    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

    if (!name_ptr) {
        return;
    }

    #pragma unroll
    for (int i = 0; i < 63; i++) {
        unsigned char c;
        bpf_probe_read_kernel(&c, sizeof(c), &name_ptr[i]);
        name[i] = c;
        if (c == '\0') {
            break;
        }
    }
    name[63] = '\0';
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

// Функция проверки доступа с уровнями логирования
static __always_inline int check_access(struct dentry *dentry, const char *operation)
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

    char name[64] = {};
    get_dentry_name(dentry, name);

    char parent_name[64] = {};
    get_parent_name(dentry, parent_name);

    int protected = is_protected_inode(dentry, target_inode);

    // Логируем только если уровень >= 2 (всё)
    if (log_level >= 2) {
        bpf_printk("BLOCKER: %s PID=%llu UID=%llu NAME=%s PARENT=%s PROTECTED=%d COMM=%s\n",
                   operation, pid, uid, name, parent_name, protected, comm);
    }

    if (uid == 0) {
        if (log_level >= 2) {
            bpf_printk("BLOCKER: %s ALLOWED ROOT\n", operation);
        }
        return 0;
    }

    if (protected) {
        // Логируем блокировку всегда, если уровень >= 1
        if (log_level >= 1) {
            bpf_printk("BLOCKER: %s BLOCKED PID=%llu UID=%llu NAME=%s PARENT=%s COMM=%s\n",
                       operation, pid, uid, name, parent_name, comm);
        }
        return -EPERM;
    }

    return 0;
}

// ============ ХУКИ ============

SEC("lsm/path_unlink")
int BPF_PROG(block_path_unlink, const struct path *dir, struct dentry *dentry)
{
    return check_access(dentry, "UNLINK");
}

SEC("lsm/path_rmdir")
int BPF_PROG(block_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    return check_access(dentry, "RMDIR");
}

SEC("lsm/path_mkdir")
int BPF_PROG(block_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dir->dentry, "MKDIR");
}

SEC("lsm/path_rename")
int BPF_PROG(block_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    int ret = check_access(old_dentry, "RENAME_OLD");
    if (ret != 0) {
        return ret;
    }
    return check_access(new_dentry, "RENAME_NEW");
}

SEC("lsm/inode_getattr")
int BPF_PROG(block_inode_getattr, const struct path *path)
{
    if (!path || !path->dentry) {
        return 0;
    }
    return check_access(path->dentry, "GETATTR");
}

SEC("lsm/file_open")
int BPF_PROG(block_file_open, struct file *file)
{
    if (!file || !file->f_path.dentry) {
        return 0;
    }
    return check_access(file->f_path.dentry, "OPEN");
}

char LICENSE[] SEC("license") = "GPL";
