#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} conn_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct conn_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&conn_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = pid_tgid >> 32;
    e->tid   = (__u32)pid_tgid;
    e->kind  = EVENT_CONN;

    e->saddr = 0;
    e->daddr = 0;
    e->sport = 0;
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}