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

// Карта для хранения целевого пути (для логирования)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} target_path_map SEC(".maps");

// Функция для безопасного копирования имени из dentry
static __always_inline void get_dentry_name(struct dentry *dentry, char *name, int size)
{
    // Заполняем нулями
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        name[i] = 0;
    }

    if (!dentry) {
        const char *unknown = "<unknown>";
        #pragma unroll
        for (int i = 0; i < 8 && unknown[i] != '\0'; i++) {
            if (i < size - 1) {
                name[i] = unknown[i];
            }
        }
        name[size - 1] = '\0';
        return;
    }

    // Читаем длину
    unsigned long len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), &dentry->d_name.len);

    if (len == 0 || len >= 64) {
        len = 63;
    }

    // Читаем указатель на имя
    const unsigned char *name_ptr = NULL;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);

    if (!name_ptr) {
        const char *unknown = "<unknown>";
        #pragma unroll
        for (int i = 0; i < 8 && unknown[i] != '\0'; i++) {
            if (i < size - 1) {
                name[i] = unknown[i];
            }
        }
        name[size - 1] = '\0';
        return;
    }

    // Копируем имя фиксированным количеством итераций
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i < len && i < size - 1) {
            unsigned char c;
            bpf_probe_read_kernel(&c, sizeof(c), &name_ptr[i]);
            name[i] = c;
        }
    }
    name[size - 1] = '\0';
}

// Общая функция проверки доступа
static __always_inline int check_access(struct inode *inode, const char *operation,
                                        struct dentry *dentry)
{
    __u32 key = 0;
    __u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    if (!inode) {
        return 0;
    }

    __u64 current_inode = inode->i_ino;
    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    __u64 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    char name[64] = {};
    if (dentry) {
        get_dentry_name(dentry, name, sizeof(name));
    } else {
        const char *unknown = "<unknown>";
        #pragma unroll
        for (int i = 0; i < 8 && unknown[i] != '\0'; i++) {
            name[i] = unknown[i];
        }
        name[sizeof(name) - 1] = '\0';
    }

    bpf_printk("BLOCKER: %s PID=%llu UID=%llu INODE=%llu TARGET=%llu NAME=%s COMM=%s\n",
               operation, pid, uid, current_inode, *target_inode, name, comm);

    if (uid == 0) {
        bpf_printk("BLOCKER: %s ALLOWED ROOT\n", operation);
        return 0;
    }

    if (current_inode == *target_inode) {
        bpf_printk("BLOCKER: %s BLOCKED\n", operation);
        return -EPERM;
    }

    return 0;
}

// Хук inode_permission
SEC("lsm/inode_permission")
int BPF_PROG(block_inode_permission, struct inode *inode, int mask)
{
    return check_access(inode, "PERMISSION", NULL);
}

// Хук path_unlink
SEC("lsm/path_unlink")
int BPF_PROG(block_file_unlink, const struct path *dir, struct dentry *dentry)
{
    struct inode *dir_inode = dir->dentry->d_inode;
    if (!dir_inode) {
        return 0;
    }
    return check_access(dir_inode, "UNLINK", dentry);
}

// Хук path_rmdir
SEC("lsm/path_rmdir")
int BPF_PROG(block_dir_rmdir, const struct path *dir, struct dentry *dentry)
{
    struct inode *dir_inode = dentry->d_inode;
    if (!dir_inode) {
        return 0;
    }
    return check_access(dir_inode, "RMDIR", dentry);
}

// Хук inode_create
SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dir, "CREATE", dentry);
}

// Хук inode_rename
SEC("lsm/inode_rename")
int BPF_PROG(block_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry)
{
    int ret = check_access(old_dir, "RENAME_OLD", old_dentry);
    if (ret != 0) {
        return ret;
    }
    return check_access(new_dir, "RENAME_NEW", new_dentry);
}

// Хук inode_link
SEC("lsm/inode_link")
int BPF_PROG(block_inode_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry)
{
    return check_access(dir, "LINK", new_dentry);
}

// Хук inode_symlink
SEC("lsm/inode_symlink")
int BPF_PROG(block_inode_symlink, struct inode *dir, struct dentry *dentry,
             const char *oldname)
{
    return check_access(dir, "SYMLINK", dentry);
}

// Хук inode_mkdir
SEC("lsm/inode_mkdir")
int BPF_PROG(block_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return check_access(dir, "MKDIR", dentry);
}

// Хук file_open
SEC("lsm/file_open")
int BPF_PROG(block_file_open, struct file *file)
{
    struct inode *inode = file->f_inode;
    if (!inode) {
        return 0;
    }
    return check_access(inode, "OPEN", NULL);
}

// Хук inode_getattr
SEC("lsm/inode_getattr")
int BPF_PROG(block_inode_getattr, const struct path *path)
{
    if (!path || !path->dentry) {
        return 0;
    }

    struct inode *inode = path->dentry->d_inode;
    if (!inode) {
        return 0;
    }

    return check_access(inode, "GETATTR", path->dentry);
}

char LICENSE[] SEC("license") = "GPL";
