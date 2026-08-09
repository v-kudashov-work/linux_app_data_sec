// log_dir_access.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TARGET_DIR "/home/user/secret"

static const char target_path[] = TARGET_DIR;
#define TARGET_LEN (sizeof(target_path) - 1)

static __always_inline int is_under_target(const char *path)
{
    int i;
    char c;

    #pragma unroll
    for (i = 0; i < TARGET_LEN; i++) {
        if (path[i] != target_path[i])
            return 0;
    }

    // Чтобы не зацепить "/home/user/secret2"
    c = path[TARGET_LEN];
    if (c != '/' && c != '\0')
        return 0;

    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    char path[256];
    int ret;

    ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0 || ret <= TARGET_LEN)
        return 0;

    if (!is_under_target(path))
        return 0;

    bpf_printk("OPEN: %s\n", path);
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(handle_file_permission, struct file *file, int mask)
{
    char path[256];
    int ret;

    ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0 || ret <= TARGET_LEN)
        return 0;

    if (!is_under_target(path))
        return 0;

    // MAY_WRITE == 2, MAY_READ == 4
    if (mask & 2)
        bpf_printk("WRITE: %s\n", path);
    else if (mask & 4)
        bpf_printk("READ: %s\n", path);
    else
        bpf_printk("PERM: %s mask=%d\n", path, mask);

    return 0;
}

char _license[] SEC("license") = "GPL";
