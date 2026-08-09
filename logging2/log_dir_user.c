// log_dir_user.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include "log_dir_access.skel.h"

static volatile sig_atomic_t stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

int main(void)
{
    struct log_dir_access_bpf *skel;
    int err;

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = log_dir_access_bpf__open();
    if (!skel) {
        fprintf(stderr, "Cannot open BPF skeleton\n");
        return 1;
    }

    err = log_dir_access_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Cannot load BPF object\n");
        goto cleanup;
    }

    err = log_dir_access_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Cannot attach LSM hooks\n");
        goto cleanup;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("BPF LSM attached. Press Ctrl-C to stop.\n");
    printf("Trace: cat /sys/kernel/tracing/trace_pipe\n");

    while (!stop)
        sleep(1);

    cleanup:
    log_dir_access_bpf__destroy(skel);
    return err ? 1 : 0;
}
