// namespace_tracer.bpf.c
// eBPF socket-level tracer for free5gc NF inter-communication.
//
// Replaces the original sched_process_exec tracepoint (which never fires for
// already-running long-lived NF processes) with socket syscall tracepoints:
//   connect / accept4 / sendmsg / recvmsg
//
// All events are filtered by cgroup ID — the container_cgroups map is
// pre-populated by the userspace loader scanning /proc at startup.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Event types ───────────────────────────────────────────────────────────────

#define EVT_CONNECT  1   // outgoing TCP connection attempt
#define EVT_ACCEPT   2   // incoming TCP connection accepted
#define EVT_SENDMSG  3   // data sent
#define EVT_RECVMSG  4   // data received

// ── Event structure sent to userspace ─────────────────────────────────────────

struct comm_event {
    __u64  ts_ns;
    __u64  cgroup_id;
    __u32  pid;
    __u32  tid;
    __u8   event_type;   // EVT_*
    __u8   af;           // AF_INET=2, AF_INET6=10
    __u8   pad[2];
    __u32  saddr[4];     // local  address (IPv4 uses [0] only)
    __u32  daddr[4];     // remote address (IPv4 uses [0] only)
    __u16  sport;
    __u16  dport;
    __s64  ret;          // syscall return value
    __u64  bytes;        // sendmsg / recvmsg byte count
    char   comm[16];
};

// ── Maps ─────────────────────────────────────────────────────────────────────

// Populated by userspace at startup with cgroup IDs of free5gc NF containers.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);   // cgroup_id
    __type(value, __u8);    // presence flag
} container_cgroups SEC(".maps");

// Ring buffer: all comm_events flow here to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB
} comm_events SEC(".maps");

// Scratch maps: save syscall entry args across the entry→exit boundary.
// connect(2) args keyed by tid.
struct connect_args {
    __u64            fd;
    struct sockaddr *addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u64);
    __type(value, struct connect_args);
} connect_scratch SEC(".maps");

// accept4(2) args keyed by tid.
struct accept_args {
    __u64            fd;
    struct sockaddr *addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u64);
    __type(value, struct accept_args);
} accept_scratch SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline int is_tracked_cgroup(void) {
    __u64 cg = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&container_cgroups, &cg) != NULL;
}

static __always_inline void read_addr(struct comm_event *e,
                                       struct sockaddr    *sa,
                                       int                 is_dest) {
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);

    if (is_dest)
        e->af = (__u8)family;

    if (family == 2 /* AF_INET */) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), sa);
        if (is_dest) {
            e->daddr[0] = sin.sin_addr.s_addr;
            e->dport    = __builtin_bswap16(sin.sin_port);
        } else {
            e->saddr[0] = sin.sin_addr.s_addr;
            e->sport    = __builtin_bswap16(sin.sin_port);
        }
    } else if (family == 10 /* AF_INET6 */) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), sa);
        if (is_dest) {
            __builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
            e->dport = __builtin_bswap16(sin6.sin6_port);
        } else {
            __builtin_memcpy(e->saddr, &sin6.sin6_addr, 16);
            e->sport = __builtin_bswap16(sin6.sin6_port);
        }
    }
}

static __always_inline struct comm_event *new_event(__u8 type) {
    struct comm_event *e = bpf_ringbuf_reserve(&comm_events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __u64 pt     = bpf_get_current_pid_tgid();
    e->ts_ns     = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid       = pt >> 32;
    e->tid       = (__u32)pt;
    e->event_type = type;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    return e;
}

// ── connect(2) ────────────────────────────────────────────────────────────────
// Outgoing SBA calls: NF consumer dials NF producer.
// Save args at entry; emit event at exit once the kernel has validated the addr.

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_tracked_cgroup())
        return 0;

    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct connect_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&connect_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_tracked_cgroup())
        return 0;

    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct connect_args *args = bpf_map_lookup_elem(&connect_scratch, &tid);
    if (!args)
        return 0;
    bpf_map_delete_elem(&connect_scratch, &tid);

    // Emit on success (0) or EINPROGRESS (-115) for non-blocking sockets.
    if (ctx->ret != 0 && ctx->ret != -115)
        return 0;

    struct comm_event *e = new_event(EVT_CONNECT);
    if (!e)
        return 0;
    read_addr(e, args->addr, 1 /* dest */);
    e->ret = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── accept4(2) ────────────────────────────────────────────────────────────────
// Incoming connections: NF producer receives a request from a consumer.
// Probe exit so the peer address is populated by the kernel before we read it.

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!is_tracked_cgroup())
        return 0;

    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct accept_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&accept_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_tracked_cgroup())
        return 0;

    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct accept_args *args = bpf_map_lookup_elem(&accept_scratch, &tid);
    if (!args)
        return 0;
    bpf_map_delete_elem(&accept_scratch, &tid);

    if (ctx->ret < 0)
        return 0;

    struct comm_event *e = new_event(EVT_ACCEPT);
    if (!e)
        return 0;
    // args->addr holds the peer (consumer) address after accept returns.
    if (args->addr)
        read_addr(e, args->addr, 1 /* treat peer as dest for display */);
    e->ret = ctx->ret; // new socket fd
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── sendmsg(2) ────────────────────────────────────────────────────────────────
// Captures data volume of outgoing SBA HTTP/2 frames.

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    if (!is_tracked_cgroup())
        return 0;

    struct comm_event *e = new_event(EVT_SENDMSG);
    if (!e)
        return 0;

    // Sum iovec lengths to get total bytes being sent.
    struct user_msghdr *msg = (struct user_msghdr *)ctx->args[1];
    struct iovec *iov    = NULL;
    __u64        iovlen  = 0;
    __u64        total   = 0;

    bpf_probe_read_user(&iov,    sizeof(iov),    &msg->msg_iov);
    bpf_probe_read_user(&iovlen, sizeof(iovlen), &msg->msg_iovlen);

    // Unrolled loop — BPF verifier requires bounded iteration.
    if (iovlen > 8) iovlen = 8;
    for (int i = 0; i < 8; i++) {
        if ((__u64)i >= iovlen) break;
        __u64 l = 0;
        bpf_probe_read_user(&l, sizeof(l), &iov[i].iov_len);
        total += l;
    }
    e->bytes = total;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── recvmsg(2) ────────────────────────────────────────────────────────────────
// Captures actual bytes received (probe exit for real byte count).

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_recvmsg_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!is_tracked_cgroup())
        return 0;
    if (ctx->ret <= 0)
        return 0;

    struct comm_event *e = new_event(EVT_RECVMSG);
    if (!e)
        return 0;
    e->bytes = (__u64)ctx->ret;
    e->ret   = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
