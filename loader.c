// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "blocker.skel.h" // Сгенерированный скелет

int main(int argc, char **argv) {
    struct blocker_bpf *skel;
    int err;
    u64 inode;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_target_folder>\n", argv[0]);
        return 1;
    }

    // Получаем инод целевой папки
    struct stat st;
    if (stat(argv[1], &st) != 0) {
        perror("stat");
        return 1;
    }
    inode = st.st_ino;
    printf("Target directory inode: %lu\n", inode);

    // Открываем и загружаем скелет eBPF-программы
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

    // Передаем инод в BPF-карту
    u32 key = 0;
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.target_inode_map), &key, &inode, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map: %d\n", err);
        goto cleanup;
    }

    // ПРИКРЕПЛЯЕМ программы к LSM-хукам
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

    printf("eBPF LSM programs attached. Protecting: %s\n", argv[1]);
    printf("  - Root (UID=0) can delete files and folders\n");
    printf("  - Non-root users are blocked\n");
    printf("Press Ctrl-C to stop...\n");

    // Ждем сигнала для завершения
    while (1) {
        sleep(1);
    }

    cleanup:
    blocker_bpf__destroy(skel);
    return err;
}
