// nrf_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
// #include "nrf_tracer.skel.h"
#include "events.h"
#include "common.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig){ stop = 1; }

/* showing event logs */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    printf("[%llu] NF=%s func=%s pid=%u tid=%u api=%s method=%s dir=%u ret=%d\n",
           e->ts,
           e->nf,
           e->func,
           e->pid,
           e->tid,
           e->api,
           e->method,
           e->direction,
           e->ret);
    return 0;
}


int main(int argc, char **argv){

    char exe_path[PATH_MAX];
    int pid;

    pid = find_nf_exe("nrf", exe_path, sizeof(exe_path));
    if (pid < 0) {
        fprintf(stderr, "failed to find nrf executable\n");
        return 1;
    }

    printf("NRF pid=%d exe=%s\n", pid, exe_path);
    // struct ring_buffer *rb = NULL;
    // struct nrf_tracer_bpf *skel = NULL;
    // int err;

    // signal(SIGINT, handle_signal);
    // signal(SIGTERM, handle_signal);

    // /* Libbpf Option Initialization Macro */
    // LIBBPF_OPTS(bpf_uprobe_opts, opts_register_entry, 
    //     .retprobe = false,
    //     .func_name = "github.com/free5gc/nrf/internal/sbi.(*Server).HTTPRegisterNFInstance");

    // LIBBPF_OPTS(bpf_uprobe_opts, opts_register_exit, 
    //     .retprobe = true,
    //     .func_name = "github.com/free5gc/nrf/internal/sbi.(*Server).HTTPRegisterNFInstance");

    // /* TODO: Load BPF skeleton & link macro */
    // skel = nrf_tracer_bpf__open_and_load();
    // if (!skel) {
    //     fprintf(stderr, "failed to open and load skeleton\n");
    //     return 1;
    // }

    // skel->links.nrf_registry_entry = bpf_program__attach_uprobe_opts(
    //     skel->progs.nrf_registry_entry,
    //     0
    // )



    // rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    // if (!rb) {
    //     fprintf(stderr, "failed to create ring buffer\n");
    //     nrf_tracer_bpf__destroy(skel);
    //     return 1;
    // }

    // while (!stop) {
    //     err = ring_buffer__poll(rb, 100);
    //     if (err < 0) {
    //         fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
    //         break;
    //     }
    // }

    // ring_buffer__free(rb);
    // nrf_tracer_bpf__destroy(skel);
    return 0;
}