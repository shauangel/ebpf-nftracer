#ifndef AMF_COMM_H
#define AMF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "amf_tracer.skel.h"
#include "sm_map.h"

/* Populate the sm_nodes / sm_edges BPF hash maps (see sm_map.c) with the
 * full 29-node / 52-edge threat-aware AMF FSM, mirrored from
 * amf/amf_state_machine.py. Call once, right after
 * amf_tracer_bpf__open_and_load(). Returns 0 on success, <0 on the first
 * bpf_map__update_elem() failure. */
int sm_map_populate(struct amf_tracer_bpf *skel);

int attach_programs(struct amf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);


/* ── Tracepoint attach / detach ─────────────────────────────────────────── */

/* One entry per syscall tracepoint to attach */
struct tp_target {
    const char      *category;   /* e.g. "syscalls"          */
    const char      *name;       /* e.g. "sys_enter_connect" */
    const char      *prog_name;  /* BPF program name in skeleton */
    struct bpf_link *link;       /* filled by attach_tracepoints */
};

int attach_tracepoints(struct amf_tracer_bpf *skel,
                       struct tp_target       *targets,
                       int                     cnt);

void detach_tracepoints(struct tp_target *targets, int cnt);

#endif