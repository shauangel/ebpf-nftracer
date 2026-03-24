// nrf_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "amf_tracer.skel.h"
#include "events.h"
#include "common.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig){ stop = 1; }

/* showing event logs */
static int handle_tok(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("[%s: %s] pid=%u tid=%u\n",e->nf, e->api, e->pid, e->tid);
    for(int i=0; i<16; i++){
        printf("%llx ", e->dbg.q[i]);
    }
    printf("\n");
    // printf("paramA: %s\n", e->dbg.buf0);
    // printf("paramB: %s\n", e->dbg.buf1);
    // printf("paramC: %s\n", e->dbg.buf2);
    // printf("paramD: %s\n", e->dbg.buf3);
    // printf("paramE: %s\n", e->dbg.buf4);
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

    /* Libbpf Option Initialization Macro */
    LIBBPF_OPTS(bpf_uprobe_opts, opts_ac_req, 
        .retprobe = false,
        .func_name = "github.com/free5gc/openapi/nrf/AccessToken.(*AccessTokenRequestApiService).AccessTokenRequest");
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load BPF skeleton & link macro */
    skel = amf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    skel->links.amf_ac_req = bpf_program__attach_uprobe_opts(
        skel->progs.amf_ac_req,
        pid,
        exe_path,
        0,
        &opts_ac_req
    );

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_tok, NULL, NULL);
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
    amf_tracer_bpf__destroy(skel);
    return 0;
}