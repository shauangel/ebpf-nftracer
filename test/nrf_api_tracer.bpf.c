#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} api_events SEC(".maps");

static __always_inline int submit_api_event(__u32 api_id)
{
    struct api_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&api_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = pid_tgid >> 32;
    e->tid   = (__u32)pid_tgid;
    e->kind  = EVENT_API;
    e->api_id = api_id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_http_register")
int nrf_http_register(struct pt_regs *ctx)
{
    return submit_api_event(API_HTTP_REGISTER_NF_INSTANCE);
}

SEC("uprobe/nrf_http_search")
int nrf_http_search(struct pt_regs *ctx)
{
    return submit_api_event(API_HTTP_SEARCH_NF_INSTANCES);
}

SEC("uprobe/nrf_http_get")
int nrf_http_get(struct pt_regs *ctx)
{
    return submit_api_event(API_HTTP_GET_NF_INSTANCE);
}