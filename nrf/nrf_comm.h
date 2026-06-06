#ifndef NRF_COMM_H
#define NRF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "nrf_tracer.skel.h"

/* ── Uprobe attach / detach ─────────────────────────────────────────────── */

int attach_programs(struct nrf_tracer_bpf *skel,
                    const char            *bin_path,
                    pid_t                  pid,
                    struct attach_target  *targets,
                    int                    cnt);

void detach_programs(struct attach_target *targets, int cnt);

/* ── Tracepoint attach / detach ─────────────────────────────────────────── */

/* One entry per syscall tracepoint to attach */
struct tp_target {
    const char      *category;   /* e.g. "syscalls"          */
    const char      *name;       /* e.g. "sys_enter_connect" */
    const char      *prog_name;  /* BPF program name in skeleton */
    struct bpf_link *link;       /* filled by attach_tracepoints */
};

int attach_tracepoints(struct nrf_tracer_bpf *skel,
                       struct tp_target       *targets,
                       int                     cnt);

void detach_tracepoints(struct tp_target *targets, int cnt);

#endif /* NRF_COMM_H */
