// nrf_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "amf_tracer.skel.h"
#include "../events.h"
#include "../common.h"
#include "amf_functions.h"

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
    struct amf_tracer_bpf *skel = NULL;
    int err;

    /* Find process binary */
    char exe_path[64];
    int pid;

    pid = find_nf_exe("amf", exe_path, sizeof(exe_path));
    if (pid < 0) {
        fprintf(stderr, "failed to find amf executable\n");
        return 1;
    }

    // Load skeleton
    skel = amf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    // Attach Subscription API probes
    attach_programs(skel, exe_path, pid, sub_funcs, sub_funcs_cnt);
    
    // Attach UE-Context API probes
    attach_programs(skel, exe_path, pid, ue_ctx_funcs, ue_ctx_funcs_cnt);

    // Attach Callback API probes
    attach_programs(skel, exe_path, pid, callback_funcs, callback_funcs_cnt);

    // Attach Event Exposure API probes
    attach_programs(skel, exe_path, pid, evnt_funcs, evnt_funcs_cnt);

    // Attach N1N2 Message API probes
    attach_programs(skel, exe_path, pid, n1n2msg_funcs, n1n2msg_funcs_cnt);

    // Attach Other API probes
    attach_programs(skel, exe_path, pid, other_funcs, other_funcs_cnt);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        amf_tracer_bpf__destroy(skel);
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
    detach_programs(sub_funcs, sub_funcs_cnt);
    detach_programs(ue_ctx_funcs, ue_ctx_funcs_cnt);
    detach_programs(callback_funcs, callback_funcs_cnt);
    detach_programs(evnt_funcs, evnt_funcs_cnt);
    detach_programs(n1n2msg_funcs, n1n2msg_funcs_cnt);
    detach_programs(other_funcs, other_funcs_cnt);
    amf_tracer_bpf__destroy(skel);
    return 0;
}