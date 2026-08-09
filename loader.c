// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "blocker.skel.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "blocker.skel.h"

// Функция для получения inode из пути
static __u64 get_inode_from_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        return 0;
    }
    return st.st_ino;
}

int main(int argc, char **argv) {
    struct blocker_bpf *skel;
    int err;
    char real_path[PATH_MAX];
    __u64 target_inode = 0;
    __u64 allowed_inode = 0;
    int log_level = 2;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <path_to_target_folder> [allowed_program_path] [log_level]\n", argv[0]);
        fprintf(stderr, "  path_to_target_folder - folder to protect (required)\n");
        fprintf(stderr, "  allowed_program_path - absolute path to program that can bypass protection (optional)\n");
        fprintf(stderr, "  log_level: 0 - no logging, 1 - log only blocked, 2 - log everything (default)\n");
        fprintf(stderr, "Example: %s /home/user/.test_app\n", argv[0]);
        fprintf(stderr, "Example with allowed: %s /home/user/.test_app /sbin/my_program/app 1\n", argv[0]);
        return 1;
    }

    // Получаем inode защищаемой папки
    if (realpath(argv[1], real_path) == NULL) {
        perror("realpath");
        return 1;
    }
    printf("Target path: %s\n", real_path);

    target_inode = get_inode_from_path(real_path);
    if (target_inode == 0) {
        fprintf(stderr, "Failed to get inode of target folder\n");
        return 1;
    }
    printf("Target inode: %lu\n", (unsigned long)target_inode);

    // Получаем inode разрешенной программы (если указана)
    if (argc >= 3) {
        char real_allowed_path[PATH_MAX];
        if (realpath(argv[2], real_allowed_path) == NULL) {
            perror("realpath for allowed program");
            fprintf(stderr, "Warning: Could not resolve '%s', continuing without allowed program\n", argv[2]);
        } else {
            printf("Allowed program path: %s\n", real_allowed_path);
            allowed_inode = get_inode_from_path(real_allowed_path);
            if (allowed_inode == 0) {
                fprintf(stderr, "Warning: Failed to get inode of allowed program\n");
            } else {
                printf("Allowed program inode: %lu\n", (unsigned long)allowed_inode);
            }
        }
    }

    if (argc == 4) {
        log_level = atoi(argv[3]);
        if (log_level < 0 || log_level > 2) {
            fprintf(stderr, "Invalid log_level. Must be 0, 1, or 2\n");
            return 1;
        }
    }
    printf("Log level: %d\n", log_level);

    skel = blocker_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = blocker_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    __u32 key = 0;

    // Передаем inode защищаемой папки
    err = bpf_map__update_elem(skel->maps.target_inode_map, &key, sizeof(key), &target_inode, sizeof(target_inode), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update target inode map: %d\n", err);
        goto cleanup;
    }

    // Передаем inode разрешенной программы (если есть)
    if (allowed_inode != 0) {
        err = bpf_map__update_elem(skel->maps.allowed_inode_map, &key, sizeof(key), &allowed_inode, sizeof(allowed_inode), BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update allowed inode map: %d\n", err);
            goto cleanup;
        }
    }

    // Передаем уровень логирования
    __u32 log_level_val = log_level;
    err = bpf_map__update_elem(skel->maps.log_level_map, &key, sizeof(key), &log_level_val, sizeof(log_level_val), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update log level map: %d\n", err);
        goto cleanup;
    }

    #define ATTACH(name) \
    skel->links.block_##name = bpf_program__attach_lsm(skel->progs.block_##name); \
    if (skel->links.block_##name) { \
        printf("Attached: " #name "\n"); \
    } else { \
        fprintf(stderr, "Failed to attach " #name "\n"); \
    }

    ATTACH(inode_getattr);
    ATTACH(file_open);
    ATTACH(path_unlink);
    ATTACH(path_rmdir);
    ATTACH(path_mkdir);
    ATTACH(path_rename);
    ATTACH(inode_create);
    ATTACH(inode_mkdir);

    printf("✅ eBPF LSM programs attached. Protecting: %s (inode: %lu)\n", real_path, (unsigned long)target_inode);
    printf("📁 GETATTR: folder is VISIBLE (block_self=0), contents PROTECTED\n");
    printf("🔒 ALL other operations: folder AND contents BLOCKED (block_self=1)\n");
    if (allowed_inode != 0) {
        printf("🔓 ALLOWED PROGRAM inode: %lu (bypasses protection)\n", (unsigned long)allowed_inode);
    } else {
        printf("🔒 No allowed program (all non-root users blocked)\n");
    }
    printf("Log level: %d\n", log_level);
    printf("Press Ctrl-C to stop...\n");

    while (1) {
        sleep(1);
    }

    cleanup:
    blocker_bpf__destroy(skel);
    return err;
}
