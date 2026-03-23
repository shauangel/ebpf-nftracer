#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include "nrf_conn_tracer.skel.h"
#include "events.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int handle_conn_event(void *ctx, void *data, size_t len)
{
    const struct conn_event *e = data;
    printf("[CONN] ts=%llu pid=%u tid=%u\n", e->ts_ns, e->pid, e->tid);
    fflush(stdout);
    return 0;
}

int main(void)
{
    struct nrf_conn_tracer_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit())
        fprintf(stderr, "failed to bump memlock: %s\n", strerror(errno));

    skel = nrf_conn_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load conn tracer skeleton\n");
        return 1;
    }

    link = bpf_program__attach(skel->progs.trace_enter_accept4);
    if (libbpf_get_error(link)) {
        err = -libbpf_get_error(link);
        link = NULL;
        fprintf(stderr, "attach conn tracer failed: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.conn_events), handle_conn_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create conn ringbuf\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing conn events...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    nrf_conn_tracer_bpf__destroy(skel);
    return err;
}