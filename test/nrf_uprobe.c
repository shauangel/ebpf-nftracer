// nrf_uprobe.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include "nrf_uprobe.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event {
    __u32 pid;
    __u32 api_id;
};

static void sig_handler(int sig)
{
    exiting = 1;
}

static int find_nrf_exe(char *exe_path, size_t exe_path_sz)
{
    DIR *dp;
    struct dirent *de;

    dp = opendir("/proc");
    if (!dp) {
        perror("opendir(/proc)");
        return -1;
    }

    while ((de = readdir(dp)) != NULL) {
        char *name = de->d_name;
        char cmdline_path[PATH_MAX];
        char proc_exe_path[PATH_MAX];
        char cmdline[4096];
        FILE *f;
        size_t nread;
        ssize_t llen;
        int pid;
        int is_pid_dir = 1;

        for (int i = 0; name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)name[i])) {
                is_pid_dir = 0;
                break;
            }
        }
        if (!is_pid_dir)
            continue;

        pid = atoi(name);
        if (pid <= 0)
            continue;

        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", name);
        f = fopen(cmdline_path, "rb");
        if (!f)
            continue;

        nread = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);

        if (nread == 0)
            continue;

        cmdline[nread] = '\0';

        if (strstr(cmdline, "./bin/nrf") == NULL &&
            strstr(cmdline, "/bin/nrf") == NULL &&
            strstr(cmdline, "free5gc/bin/nrf") == NULL) {
            continue;
        }

        snprintf(proc_exe_path, sizeof(proc_exe_path), "/proc/%s/exe", name);
        llen = readlink(proc_exe_path, exe_path, exe_path_sz - 1);
        if (llen < 0)
            continue;

        exe_path[llen] = '\0';
        closedir(dp);
        return pid;
    }

    closedir(dp);
    return -1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    const char *api = "UNKNOWN";

    switch (e->api_id) {
    case 1:
        api = "HTTPRegisterNFInstance";
        break;
    case 2:
        api = "HTTPSearchNFInstances";
        break;
    case 3:
        api = "HTTPGetNFInstance";
        break;
    default:
        break;
    }

    printf("api=%s\n", api);
    fflush(stdout);
    return 0;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;
    struct nrf_uprobe_bpf *skel = NULL;
    char exe_path[PATH_MAX];
    int target_pid;
    int err = 0;

    LIBBPF_OPTS(bpf_uprobe_opts, opts_register,
        .retprobe = false,
        .func_name = "github.com/free5gc/nrf/internal/sbi.(*Server).HTTPRegisterNFInstance"
    );

    LIBBPF_OPTS(bpf_uprobe_opts, opts_search,
        .retprobe = false,
        .func_name = "github.com/free5gc/nrf/internal/sbi.(*Server).HTTPSearchNFInstances"
    );

    LIBBPF_OPTS(bpf_uprobe_opts, opts_get,
        .retprobe = false,
        .func_name = "github.com/free5gc/nrf/internal/sbi.(*Server).HTTPGetNFInstance"
    );

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }

    target_pid = find_nrf_exe(exe_path, sizeof(exe_path));
    if (target_pid < 0) {
        fprintf(stderr, "failed to find NRF process from /proc/*/cmdline\n");
        return 1;
    }

    printf("Found NRF pid=%d exe=%s\n", target_pid, exe_path);

    skel = nrf_uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }

    link1 = bpf_program__attach_uprobe_opts(
        skel->progs.nrf_http_register,
        target_pid,
        exe_path,
        0,
        &opts_register
    );
    if (libbpf_get_error(link1)) {
        err = -libbpf_get_error(link1);
        link1 = NULL;
        fprintf(stderr, "failed to attach HTTPRegisterNFInstance by symbol: %d\n", err);
        goto cleanup;
    }

    link2 = bpf_program__attach_uprobe_opts(
        skel->progs.nrf_http_search,
        target_pid,
        exe_path,
        0,
        &opts_search
    );
    if (libbpf_get_error(link2)) {
        err = -libbpf_get_error(link2);
        link2 = NULL;
        fprintf(stderr, "failed to attach HTTPSearchNFInstances by symbol: %d\n", err);
        goto cleanup;
    }

    link3 = bpf_program__attach_uprobe_opts(
        skel->progs.nrf_http_get,
        target_pid,
        exe_path,
        0,
        &opts_get
    );
    if (libbpf_get_error(link3)) {
        err = -libbpf_get_error(link3);
        link3 = NULL;
        fprintf(stderr, "failed to attach HTTPGetNFInstance by symbol: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing NRF uprobes... Ctrl-C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link1);
    bpf_link__destroy(link2);
    bpf_link__destroy(link3);
    nrf_uprobe_bpf__destroy(skel);
    return err;
}