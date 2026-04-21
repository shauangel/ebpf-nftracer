#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../events.h"

char LICENSE[] SEC("license") = "GPL";

// Define map structure (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");


/* ------------- UE Authentication ------------- */
// Authentication Aka Confirm Request
SEC("uprobe/ausf_auth_aka_confirm")
int ausf_auth_aka_confirm(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AUSF", 4);
    __builtin_memcpy(e->api, "AUSFAuthAkaConfirm", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// UE Authentication Post Request
SEC("uprobe/ausf_ue_auth_post")
int ausf_ue_auth_post(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AUSF", 4);
    __builtin_memcpy(e->api, "AUSFUEAuthPost", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// EAP Authentication Confirm Request
SEC("uprobe/ausf_eap_auth_confirm")
int ausf_eap_auth_confirm(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AUSF", 4);
    __builtin_memcpy(e->api, "AUSFEAPAuthConfirm", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
