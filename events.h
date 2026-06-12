/* events.h — shared event schema for BPF programs and userspace loader.
 *
 * Changes from original:
 *   + EVT_* type constants
 *   + struct event gains: type, af, src/dest ip+port, bytes, ret
 *   + direction_type and debug_args kept as-is
 */

#ifndef __EVENTS_H__
#define __EVENTS_H__

/* ── Event type constants ───────────────────────────────────────────────── */

#define EVT_API_CALL   0   /* NRF Go function invoked (uprobe)       */
#define EVT_CONNECT    1   /* outgoing TCP connect()                  */
#define EVT_ACCEPT     2   /* incoming TCP accept4() — peer addr      */
#define EVT_WRITE      3   /* write() bytes sent                      */
#define EVT_READ       4   /* read()  bytes received                  */

/* ── Unchanged helpers ─────────────────────────────────────────────────── */

enum direction_type {
    IN  = 0,
    OUT = 1,
};

struct debug_args {
    __u64 arg1, arg2, arg3, arg4;
    __u64 q[16];
    char buf0[64], buf1[64], buf2[64], buf3[64], buf4[64];
};

/* ── Event struct ──────────────────────────────────────────────────────── */
/*
 * Field usage by event type:
 *
 *   EVT_API_CALL  →  type, ts, pid, tid, cid, nf, api, auth_id, scope
 *   EVT_CONNECT   →  type, ts, pid, tid, cid, nf, af, src/dest ip+port
 *   EVT_ACCEPT    →  type, ts, pid, tid, cid, nf, af, src/dest ip+port
 *   EVT_WRITE     →  type, ts, pid, tid, cid, nf, bytes
 *   EVT_READ      →  type, ts, pid, tid, cid, nf, bytes, ret
 *
 * All unused fields are zeroed by the BPF program.
 */
struct event {
    /* classification */
    __u8  type;              /* EVT_*                                 */
    __u8  af;                /* address family: AF_INET=2 (connect/accept) */
    __u8  _pad[2];           /* explicit alignment padding            */

    /* timestamp */
    __u64 ts;                /* ktime_get_ns()                        */

    /* process (kernel) */
    __u32 pid;               /* process id                            */
    __u32 tid;               /* thread id                             */
    __u64 cid;               /* cgroup id                             */

    /* application (L7) */
    char nf[8];              /* NF name, e.g. "NRF"                  */
    char api[32];            /* 3GPP operation (EVT_API_CALL only)    */

    /* network L3-L4 (EVT_CONNECT / EVT_ACCEPT) */
    __u32 src_ip;            /* local  IPv4 address (network order)   */
    __u32 dest_ip;           /* remote IPv4 address (network order)   */
    __u16 src_port;          /* local  port         (host order)      */
    __u16 dest_port;         /* remote port         (host order)      */

    /* data volume (EVT_WRITE / EVT_READ) */
    __u64 bytes;             /* byte count                            */
    __s64 ret;               /* syscall return value                  */

    /* auth (EVT_API_CALL) */
    char auth_id[32];
    char scope[32];

    /* debug */
    struct debug_args dbg;
};

#endif /* __EVENTS_H__ */
