// blocker.bpf.c
// #include <linux/types.h>
// #include <linux/errno.h>

#ifndef _BOOL_H
#define _BOOL_H

#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86

typedef unsigned char bool;
#define true 1
#define false 0

#endif // _BOOL_H

#include "vmlinux.h"
#include <linux/types.h>
#include <linux/bpf.h>

// #ifndef bpf_helper_defs_DEF
// #define bpf_helper_defs_DEF
// #include "bpf/bpf_helper_defs.h"
// #endif
#include <bpf/usdt.bpf.h>

#include <bpf/bpf_helpers.h>
// #include <bpf/usdt.bpf.h>
#include <bpf/bpf_tracing.h>

// Целевая папка: /home/user/.test_app
// Передаем инод через BPF-карту
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_inode_map SEC(".maps");

// Хук для блокировки УДАЛЕНИЯ файлов
SEC("lsm/path_unlink")
int BPF_PROG(block_file_unlink, const struct path *dir, struct dentry *dentry)
{
    u32 key = 0;
    u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0; // Если карта не инициализирована, пропускаем проверку
    }

    // Получаем UID текущего процесса
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Если пользователь root (UID == 0) - разрешаем удаление
    if (uid == 0) {
        return 0;
    }

    // Получаем инод директории, в которой находится файл
    struct inode *dir_inode = dir->dentry->d_inode;
    if (!dir_inode) {
        return 0;
    }

    u64 current_inode = dir_inode->i_ino;

    // Если это наша целевая папка - блокируем удаление
    if (current_inode == *target_inode) {
        bpf_printk("Blocked file deletion in target directory by UID=%llu\n", uid);
        return -EPERM; // Отказано в доступе
    }

    return 0; // Разрешаем удаление
}

// Хук для блокировки УДАЛЕНИЯ папок (rmdir)
SEC("lsm/path_rmdir")
int BPF_PROG(block_dir_rmdir, const struct path *dir, struct dentry *dentry)
{
    u32 key = 0;
    u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    // Получаем UID текущего процесса
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Если пользователь root (UID == 0) - разрешаем удаление
    if (uid == 0) {
        return 0;
    }

    // Получаем инод самой удаляемой папки
    struct inode *dir_inode = d_inode(dentry);
    if (!dir_inode) {
        return 0;
    }

    u64 current_inode = dir_inode->i_ino;

    // Если это наша целевая папка - блокируем удаление
    if (current_inode == *target_inode) {
        bpf_printk("Blocked directory deletion of target folder by UID=%llu\n", uid);
        return -EPERM; // Отказано в доступе
    }

    return 0; // Разрешаем удаление
}

// Хук для блокировки СОЗДАНИЯ файлов в папке
SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    u32 key = 0;
    u64 *target_inode = bpf_map_lookup_elem(&target_inode_map, &key);
    if (!target_inode) {
        return 0;
    }

    // Получаем UID текущего процесса
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Если пользователь root (UID == 0) - разрешаем
    if (uid == 0) {
        return 0;
    }

    // Проверяем инод родительской директории
    u64 current_inode = dir->i_ino;

    if (current_inode == *target_inode) {
        bpf_printk("Blocked file creation in target directory by UID=%llu\n", uid);
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
