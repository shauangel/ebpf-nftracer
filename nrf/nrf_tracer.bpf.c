// nrf_tracer.bpf.c
//
// Two probe classes:
//
//  UPROBES     — attached by the loader to specific NRF Go symbols.
//                Fire only for the target PID; no extra cgroup filter needed.
//                Emit EVT_API_CALL events.
//
//  TRACEPOINTS — global syscall hooks filtered by nrf_cgroup_map so only
//                events from the NRF container are kept.
//                Emit EVT_CONNECT / EVT_ACCEPT / EVT_WRITE / EVT_READ.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

/* ── Maps ─────────────────────────────────────────────────────────────── */

/* Ring buffer — all events flow here */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   /* 16 MB */
} events SEC(".maps");

/* Single-entry array: the NRF container's cgroupv2 ID.
 * Written by the loader immediately after skeleton load. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} nrf_cgroup_map SEC(".maps");

/* Scratch: save connect() entry args across the syscall boundary */
struct _connect_args { __u64 fd; struct sockaddr *addr; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);           /* tid */
    __type(value, struct _connect_args);
} connect_scratch SEC(".maps");

/* Scratch: save accept4() entry args across the syscall boundary */
struct _accept_args { __u64 fd; struct sockaddr *addr; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, struct _accept_args);
} accept_scratch SEC(".maps");

/* ── Helpers ───────────────────────────────────────────────────────────── */

/* True if calling process is in the NRF container cgroup */
static __always_inline int is_nrf_cgroup(void)
{
    __u32 key = 0;
    __u64 *stored = bpf_map_lookup_elem(&nrf_cgroup_map, &key);
    if (!stored || *stored == 0)
        return 0;
    return bpf_get_current_cgroup_id() == *stored;
}

/* Reserve a ring-buffer slot and fill common fields */
static __always_inline struct event *new_event(__u8 type)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    e->type = type;
    e->ts   = bpf_ktime_get_ns();
    __u64 pt = bpf_get_current_pid_tgid();
    e->pid  = (__u32)(pt >> 32);
    e->tid  = (__u32)pt;
    e->cid  = bpf_get_current_cgroup_id();
    __builtin_memcpy(e->nf, "NRF", 4);
    return e;
}

/* Read IPv4 sockaddr fields into an event (connect / accept) */
static __always_inline void read_sockaddr_in(struct event *e,
                                              struct sockaddr *sa)
{
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
    if (family != 2 /* AF_INET */)
        return;

    e->af = 2;
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), sa);
    e->dest_ip   = sin.sin_addr.s_addr;
    e->dest_port = __builtin_bswap16(sin.sin_port);
}


/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 — NRF API uprobes  (original, reformatted to use new_event)
 * ═══════════════════════════════════════════════════════════════════════ */

/* NF Management */

SEC("uprobe/nrf_nf_register")
int nrf_nf_register(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NFRegister", 10);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_nf_deregister")
int nrf_nf_deregister(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NFDeregister", 12);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_get_nf_inst")
int nrf_get_nf_inst(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "GetNFInstance", 13);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_get_nf_inst_list")
int nrf_get_nf_inst_list(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "GetNFInstanceList", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_update_nf_inst")
int nrf_update_nf_inst(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "UpdateNFInstance", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_create_sub")
int nrf_create_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "CreateSubscription", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_remove_sub")
int nrf_remove_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "RemoveSubscription", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_update_sub")
int nrf_update_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "UpdateSubscription", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Authentication */

SEC("uprobe/nrf_access_token")
int nrf_access_token(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AccessToken", 11);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* NF Discovery */

SEC("uprobe/nrf_nf_discovery")
int nrf_nf_discovery(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NFDiscovery", 11);
    bpf_ringbuf_submit(e, 0);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 — Socket syscall tracepoints  (new, cgroup-filtered)
 * ═══════════════════════════════════════════════════════════════════════ */

/* connect(2) — outgoing TCP connections (NRF acting as HTTP/2 client) */

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _connect_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&connect_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _connect_args *a = bpf_map_lookup_elem(&connect_scratch, &tid);
    if (!a) return 0;
    bpf_map_delete_elem(&connect_scratch, &tid);

    /* success or EINPROGRESS (-115) for non-blocking sockets */
    if (ctx->ret != 0 && ctx->ret != -115) return 0;

    struct event *e = new_event(EVT_CONNECT);
    if (!e) return 0;
    read_sockaddr_in(e, a->addr);
    e->ret = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* accept4(2) — incoming connections (NRF acting as HTTP/2 server) */

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _accept_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&accept_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _accept_args *a = bpf_map_lookup_elem(&accept_scratch, &tid);
    if (!a) return 0;
    bpf_map_delete_elem(&accept_scratch, &tid);

    if (ctx->ret < 0) return 0;   /* failed accept */

    struct event *e = new_event(EVT_ACCEPT);
    if (!e) return 0;
    if (a->addr)
        read_sockaddr_in(e, a->addr);  /* fills peer (caller) address */
    e->ret = ctx->ret;                 /* new socket fd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* write(2) — data sent by NRF (HTTP/2 frames, response bodies) */

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    __u64 count = (size_t)ctx->args[2];
    if (count == 0) return 0;

    struct event *e = new_event(EVT_WRITE);
    if (!e) return 0;
    e->bytes = count;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* read(2) — data received by NRF; probe exit for the actual byte count */

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_nrf_cgroup()) return 0;
    if (ctx->ret <= 0) return 0;

    struct event *e = new_event(EVT_READ);
    if (!e) return 0;
    e->bytes = (__u64)ctx->ret;
    e->ret   = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
