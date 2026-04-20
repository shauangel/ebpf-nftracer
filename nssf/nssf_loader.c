// nssf_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "nssf_tracer.skel.h"
#include "../events.h"
#include "../common.h"
#include "nssf_functions.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig){ stop = 1; }

/* Triggered event handler */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("%s: %s\n",e->nf, e->api);
    return 0;
}


int main(int argc, char **argv){
    struct ring_buffer *rb = NULL;
    struct nssf_tracer_bpf *skel = NULL;
    int err;

    /* Find process binary */
    char exe_path[64];
    int pid;

    pid = find_nf_exe("nssf", exe_path, sizeof(exe_path));
    if (pid < 0) {
        fprintf(stderr, "failed to find nssf executable\n");
        return 1;
    }

    // Load skeleton
    skel = nssf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    /* -------------- TODO -------------- */
    // Use nssf_comm function to attach multiple probes
    // attach_programs(skel, exe_path, pid, sub_funcs, sub_funcs_cnt);
    

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        nssf_tracer_bpf__destroy(skel);
        return 1;
    }

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    nssf_tracer_bpf__destroy(skel);
    return 0;
}