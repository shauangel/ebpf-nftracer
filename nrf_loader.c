// nrf_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "nrf_tracer.skel.h"
#include "events.h"
#include "common.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig){ stop = 1; }

/* showing event logs */
// static int handle_args(void *ctx, void *data, size_t data_sz)
// {
//     const struct event *e = data;
//     printf("[%s: %s] pid=%u tid=%u\n",e->nf, e->api, e->pid, e->tid);
//     printf("p1=%llx l1=%llu s1=%s\n", e->p1, e->l1, e->s1);
//     printf("p3=%llx l3=%llu s3=%s\n", e->p3, e->l3, e->s3);
//     printf("p4=%llx l4=%llu s4=%s\n", e->p4, e->l4, e->s4);
//     return 0;
// }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("[%s: %s] pid=%u tid=%u\n",e->nf, e->api, e->pid, e->tid);
    // for(int i=0; i<16; i++){
    //     printf("%llx ", e->dbg.q[i]);
    // }
    // printf("\n");
    if(!e->dbg.buf0)
        printf("paramA: %s\n", e->dbg.buf0);
    if(!e->dbg.buf1)
        printf("paramB: %s\n", e->dbg.buf1);
    if(!e->dbg.buf2)
        printf("paramC: %s\n", e->dbg.buf2);
    if(!e->dbg.buf3)
        printf("paramD: %s\n", e->dbg.buf3);
    if(!e->dbg.buf4)
        printf("paramE: %s\n", e->dbg.buf4);

    // printf("arg1=%llx arg2=%llx arg3=%llx arg4=%llx\n", e->arg1, e->arg2, e->arg3, e->arg4);
    // printf("arg4: \n");
    // for(int i=0; i<64; i++){
    //     printf("%02x ", (unsigned char)e->probe_test[i]);
    // }
    // printf("\n");

    // printf("arg2-q0: \n");
    // for(int i=0; i<64; i++){
    //     printf("%02x ", (unsigned char)e->buf0[i]);
    // }
    // printf("\n");


    // printf("arg2-q1: \n");
    // for(int i=0; i<64; i++){
    //     printf("%02x ", (unsigned char)e->buf1[i]);
    // }
    // printf("\n");
    return 0;
}


int main(int argc, char **argv){
    struct ring_buffer *rb = NULL;
    struct nrf_tracer_bpf *skel = NULL;
    int err;

    /* Find process binary */
    char exe_path[64];
    int pid;

    pid = find_nf_exe("nrf", exe_path, sizeof(exe_path));
    if (pid < 0) {
        fprintf(stderr, "failed to find nrf executable\n");
        return 1;
    }
    // printf("NRF pid=%d exe=%s\n", pid, exe_path);


    /* Libbpf Option Initialization Macro */
    LIBBPF_OPTS(bpf_uprobe_opts, opts_reg_args, 
        .retprobe = false,
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).NFRegisterProcedure");
    

    LIBBPF_OPTS(bpf_uprobe_opts, opts_ac_args, 
        .retprobe = false,
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).AccessTokenProcedure");
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load BPF skeleton & link macro */
    skel = nrf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }

    skel->links.nrf_reg_args = bpf_program__attach_uprobe_opts(
        skel->progs.nrf_reg_args,
        pid,
        exe_path,
        0,
        &opts_reg_args
    );

    skel->links.nrf_ac_args = bpf_program__attach_uprobe_opts(
        skel->progs.nrf_ac_args,
        pid,
        exe_path,
        0,
        &opts_ac_args
    );

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        nrf_tracer_bpf__destroy(skel);
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
    nrf_tracer_bpf__destroy(skel);
    return 0;
}