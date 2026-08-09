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

int main(int argc, char **argv) {
    struct blocker_bpf *skel;
    int err;
    char target_path[256];
    char real_path[PATH_MAX];
    __u64 inode;
    struct stat st;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_target_folder>\n", argv[0]);
        fprintf(stderr, "Example: %s /home/user/.test_app\n", argv[0]);
        return 1;
    }

    // 1. Получаем абсолютный путь
    if (realpath(argv[1], real_path) == NULL) {
        perror("realpath");
        fprintf(stderr, "Error: path '%s' does not exist or cannot be resolved\n", argv[1]);
        return 1;
    }
    printf("Real path: %s\n", real_path);

    // 2. Получаем inode из пути
    if (stat(real_path, &st) != 0) {
        perror("stat");
        return 1;
    }
    inode = st.st_ino;
    printf("Target directory inode: %lu\n", (unsigned long)inode);

    // 3. Копируем путь в буфер (на всякий случай)
    strncpy(target_path, real_path, sizeof(target_path) - 1);
    target_path[sizeof(target_path) - 1] = '\0';

    // 4. Открываем скелет
    skel = blocker_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 5. Загружаем
    err = blocker_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 6. Передаем inode в BPF-карту
    __u32 key = 0;
    err = bpf_map__update_elem(skel->maps.target_inode_map, &key, sizeof(key), &inode, sizeof(inode), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update inode map: %d\n", err);
        goto cleanup;
    }

    // 7. (Опционально) Передаем путь в BPF-карту для логирования
    err = bpf_map__update_elem(skel->maps.target_path_map, &key, sizeof(key), target_path, sizeof(target_path), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update path map: %d\n", err);
        goto cleanup;
    }

    // 8. Прикрепляем программы
    skel->links.block_file_unlink = bpf_program__attach_lsm(skel->progs.block_file_unlink);
    if (!skel->links.block_file_unlink) {
        fprintf(stderr, "Failed to attach LSM program for unlink\n");
        err = -1;
        goto cleanup;
    }

    skel->links.block_dir_rmdir = bpf_program__attach_lsm(skel->progs.block_dir_rmdir);
    if (!skel->links.block_dir_rmdir) {
        fprintf(stderr, "Failed to attach LSM program for rmdir\n");
        err = -1;
        goto cleanup;
    }

    skel->links.block_file_create = bpf_program__attach_lsm(skel->progs.block_file_create);
    if (!skel->links.block_file_create) {
        fprintf(stderr, "Failed to attach LSM program for create\n");
        err = -1;
        goto cleanup;
    }

    printf("✅ eBPF LSM programs attached. Protecting: %s\n", target_path);
    printf("   Inode: %lu\n", (unsigned long)inode);
    printf("   Root (UID=0) can access everything\n");
    printf("   Non-root users are blocked\n");
    printf("Press Ctrl-C to stop...\n");

    // 9. Ждем
    while (1) {
        sleep(1);
    }

    cleanup:
    blocker_bpf__destroy(skel);
    return err;
}
