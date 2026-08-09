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

// BTF-стиль определения карты
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_inode_map SEC(".maps");

// Хук для блокировки УДАЛЕНИЯ файлов
SEC("lsm/path_unlink")
int BPF_PROG(block_file_unlink, struct path *dir, struct dentry *dentry)
// int block_file_unlink(struct path *dir, struct dentry *dentry)
{
    __u32 key = 0;
    __u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) {
        return 0;
    }

    // Напрямую обращаемся к полю d_inode структуры dentry
    struct inode *dir_inode = dentry->d_inode;
    if (!dir_inode) {
        return 0;
    }

    __u64 current_inode = dir_inode->i_ino;

    if (current_inode == *target_inode) {
        bpf_printk("Blocked file deletion in target directory by UID=%llu\n", uid);
        return -EPERM;
    }

    return 0;
}

// Хук для блокировки УДАЛЕНИЯ папок
SEC("lsm/path_rmdir")
int BPF_PROG(block_dir_rmdir, struct path *dir, struct dentry *dentry)
// int block_dir_rmdir(struct path *dir, struct dentry *dentry)
{
    __u32 key = 0;
    __u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) {
        return 0;
    }

    // Напрямую обращаемся к полю d_inode структуры dentry
    struct inode *dir_inode = dentry->d_inode;
    if (!dir_inode) {
        return 0;
    }

    __u64 current_inode = dir_inode->i_ino;

    if (current_inode == *target_inode) {
        bpf_printk("Blocked directory deletion of target folder by UID=%llu\n", uid);
        return -EPERM;
    }

    return 0;
}

// Хук для блокировки СОЗДАНИЯ файлов
SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode)
// int block_file_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    __u32 key = 0;
    __u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) {
        return 0;
    }

    __u64 current_inode = dir->i_ino;

    if (current_inode == *target_inode) {
        bpf_printk("Blocked file creation in target directory by UID=%llu\n", uid);
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
