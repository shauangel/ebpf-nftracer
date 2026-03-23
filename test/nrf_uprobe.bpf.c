// nrf_uprobe.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 api_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int submit_event(__u32 api_id)
{
    struct event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid_tgid >> 32;
    e->api_id = api_id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_http_register")
int BPF_KPROBE(nrf_http_register)
{
    return submit_event(1);
}

SEC("uprobe/nrf_http_search")
int BPF_KPROBE(nrf_http_search)
{
    return submit_event(2);
}


SEC("uprobe/nrf_http_get")
int BPF_KPROBE(nrf_http_get)
{
    return submit_event(3);
}
