// amf_loader.c
//
// Startup sequence:
//   1. find_nf()            → PID                (comm-based, /proc scan)
//   2. /proc/<pid>/exe      → binary path        (container-aware, no readlink)
//   3. open_and_load()      → BPF skeleton
//   4. attach_programs()    × 6 uprobe groups    (sub / ue-ctx / callback /
//                                                  event / n1n2msg / other)
//   5. ring_buffer__poll()  → event loop

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "amf_tracer.skel.h"
#include "../events.h"
#include "../common.h"
#include "amf_functions.h"
#include "amf_comm.h"

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { (void)sig; stop = 1; }

/* ── Ring buffer event handler ──────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    const struct event *e = data;
    printf("%s: %s\n", e->nf, e->api);
    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    int err = 0;
    struct amf_tracer_bpf *skel = NULL;
    struct ring_buffer    *rb   = NULL;

    /* 1. Discover AMF container process */
    char  exe_path[256] = {};
    pid_t pid;

    printf("[*] Looking for AMF container process...\n");
    pid = find_nf("amf");
    if (pid < 0) {
        fprintf(stderr, "error: AMF not found — is the container running?\n");
        return 1;
    }
    printf("    pid=%-6d\n", pid);

    /* 2. Resolve binary path via /proc/<pid>/exe
     *    Works for container processes without readlink — libbpf opens the
     *    symlink directly, following it through the overlay filesystem. */
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    printf("    exe=%s\n\n", exe_path);

    /* 3. Load BPF skeleton */
    skel = amf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        return 1;
    }

    /* 4. Attach AMF API uprobes */
    printf("[*] Attaching uprobes...\n");
    if (attach_programs(skel, exe_path, pid, sub_funcs,      sub_funcs_cnt)      < 0 ||
        attach_programs(skel, exe_path, pid, ue_ctx_funcs,   ue_ctx_funcs_cnt)   < 0 ||
        attach_programs(skel, exe_path, pid, callback_funcs, callback_funcs_cnt) < 0 ||
        attach_programs(skel, exe_path, pid, evnt_funcs,     evnt_funcs_cnt)     < 0 ||
        attach_programs(skel, exe_path, pid, n1n2msg_funcs,  n1n2msg_funcs_cnt)  < 0 ||
        attach_programs(skel, exe_path, pid, other_funcs,    other_funcs_cnt)    < 0) {
        err = 1;
        goto cleanup;
    }

    /* 5. Ring buffer + event loop */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: ring_buffer__new failed\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\n[*] Tracing AMF (pid=%d). Ctrl+C to stop.\n\n", pid);
    printf("%-4s  %s\n", "NF", "API");
    printf("%-4s  %s\n", "────", "────────────────────────────────");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
        err = 0;
    }

cleanup:
    printf("\n[*] Detaching...\n");
    ring_buffer__free(rb);
    detach_programs(sub_funcs,      sub_funcs_cnt);
    detach_programs(ue_ctx_funcs,   ue_ctx_funcs_cnt);
    detach_programs(callback_funcs, callback_funcs_cnt);
    detach_programs(evnt_funcs,     evnt_funcs_cnt);
    detach_programs(n1n2msg_funcs,  n1n2msg_funcs_cnt);
    detach_programs(other_funcs,    other_funcs_cnt);
    amf_tracer_bpf__destroy(skel);
    return err;
}
