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

int main(int argc, char **argv) {
    struct blocker_bpf *skel;
    int err;
    char real_path[PATH_MAX];
    __u64 inode;
    struct stat st;
    int log_level = 2;  // По умолчанию логируем всё

    // Обработка аргументов
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <path_to_target_folder> [log_level]\n", argv[0]);
        fprintf(stderr, "  log_level: 0 - no logging, 1 - log only blocked, 2 - log everything (default)\n");
        fprintf(stderr, "Example: %s /home/user/.test_app 1\n", argv[0]);
        return 1;
    }

    if (argc == 3) {
        log_level = atoi(argv[2]);
        if (log_level < 0 || log_level > 2) {
            fprintf(stderr, "Invalid log_level. Must be 0, 1, or 2\n");
            return 1;
        }
    }

    printf("Log level: %d\n", log_level);

    if (realpath(argv[1], real_path) == NULL) {
        perror("realpath");
        return 1;
    }
    printf("Real path: %s\n", real_path);

    if (stat(real_path, &st) != 0) {
        perror("stat");
        return 1;
    }
    inode = st.st_ino;
    printf("Target directory inode: %lu\n", (unsigned long)inode);

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

    // Передаем inode в BPF-карту
    __u32 key = 0;
    err = bpf_map__update_elem(skel->maps.target_inode_map, &key, sizeof(key), &inode, sizeof(inode), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update inode map: %d\n", err);
        goto cleanup;
    }

    // Передаем уровень логирования в BPF-карту
    __u32 log_level_val = log_level;
    err = bpf_map__update_elem(skel->maps.log_level_map, &key, sizeof(key), &log_level_val, sizeof(log_level_val), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update log level map: %d\n", err);
        goto cleanup;
    }

    // Прикрепляем хуки
    skel->links.block_path_unlink = bpf_program__attach_lsm(skel->progs.block_path_unlink);
    if (skel->links.block_path_unlink) {
        printf("Attached: path_unlink\n");
    } else {
        fprintf(stderr, "Failed to attach path_unlink\n");
    }

    skel->links.block_path_rmdir = bpf_program__attach_lsm(skel->progs.block_path_rmdir);
    if (skel->links.block_path_rmdir) {
        printf("Attached: path_rmdir\n");
    } else {
        fprintf(stderr, "Failed to attach path_rmdir\n");
    }

    skel->links.block_path_mkdir = bpf_program__attach_lsm(skel->progs.block_path_mkdir);
    if (skel->links.block_path_mkdir) {
        printf("Attached: path_mkdir\n");
    } else {
        fprintf(stderr, "Failed to attach path_mkdir\n");
    }

    skel->links.block_path_rename = bpf_program__attach_lsm(skel->progs.block_path_rename);
    if (skel->links.block_path_rename) {
        printf("Attached: path_rename\n");
    } else {
        fprintf(stderr, "Failed to attach path_rename\n");
    }

    skel->links.block_inode_getattr = bpf_program__attach_lsm(skel->progs.block_inode_getattr);
    if (skel->links.block_inode_getattr) {
        printf("Attached: inode_getattr\n");
    } else {
        fprintf(stderr, "Failed to attach inode_getattr\n");
    }

    skel->links.block_file_open = bpf_program__attach_lsm(skel->progs.block_file_open);
    if (skel->links.block_file_open) {
        printf("Attached: file_open\n");
    } else {
        fprintf(stderr, "Failed to attach file_open\n");
    }

    printf("✅ eBPF LSM programs attached. Protecting: %s (inode: %lu)\n", real_path, (unsigned long)inode);
    printf("Log level: %d (0=off, 1=blocked only, 2=everything)\n", log_level);
    printf("Press Ctrl-C to stop...\n");

    while (1) {
        sleep(1);
    }

    cleanup:
    blocker_bpf__destroy(skel);
    return err;
}
