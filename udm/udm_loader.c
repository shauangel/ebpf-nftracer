// udm_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "udm_tracer.skel.h"
#include "../events.h"
#include "../common.h"
#include "udm_functions.h"

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
    struct udm_tracer_bpf *skel = NULL;
    int err;

    /* Find process binary */
    char exe_path[64];
    int pid;

    pid = find_nf_exe("udm", exe_path, sizeof(exe_path));
    if (pid < 0) {
        fprintf(stderr, "failed to find udm executable\n");
        return 1;
    }

    // Load skeleton
    skel = udm_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    // Attach Event Exposure Functions
    attach_programs(skel, exe_path, pid, evnt_exp_funcs, evnt_exp_funcs_cnt);
    
    // Attach Generate Authentication Data Functions
    attach_programs(skel, exe_path, pid, gen_auth_funcs, gen_auth_funcs_cnt);

    // Attach Parameter Provision Functions
    attach_programs(skel, exe_path, pid, param_prov_funcs, param_prov_funcs_cnt);

    // Attach Subscriber Data Management Functions
    attach_programs(skel, exe_path, pid, subscriber_funcs, subscriber_funcs_cnt);

    // Attach UE Context Management Functions
    attach_programs(skel, exe_path, pid, ue_ctx_mngmt_funcs, ue_ctx_mngmt_funcs_cnt);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        udm_tracer_bpf__destroy(skel);
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
    detach_programs(skel, evnt_exp_funcs, evnt_exp_funcs_cnt);
    detach_programs(skel, gen_auth_funcs, gen_auth_funcs_cnt);
    detach_programs(skel, param_prov_funcs, param_prov_funcs_cnt);
    detach_programs(skel, subscriber_funcs, subscriber_funcs_cnt);
    detach_programs(skel, ue_ctx_mngmt_funcs, ue_ctx_mngmt
    udm_tracer_bpf__destroy(skel);
    return 0;
}