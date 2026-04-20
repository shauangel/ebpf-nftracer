#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

// Define map structure (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");


/* ------------- NF_Management ------------- */
// NF Register probe
SEC("uprobe/nrf_nf_register")
int nrf_nf_register(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFNFRegister", 13);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// NF Deregister probe
SEC("uprobe/nrf_nf_deregister")
int nrf_nf_deregister(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFNFDeregister", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get NF Instance probe
SEC("uprobe/nrf_get_nf_inst")
int nrf_get_nf_inst(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFGetNFInstance", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get NF Instances probe
SEC("uprobe/nrf_get_nf_inst_list")
int nrf_get_nf_inst_list(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFGetNFInstanceList", 20);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update NF Instance probe
SEC("uprobe/nrf_update_nf_inst")
int nrf_update_nf_inst(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFUpdateNFInstance", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Create Subscription probe
SEC("uprobe/nrf_create_sub")
int nrf_create_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFCreateSubscription", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Remove Subscription probe
SEC("uprobe/nrf_remove_sub")
int nrf_remove_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFRemoveSubscription", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update Subscription probe
SEC("uprobe/nrf_update_sub")
int nrf_update_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFUpdateSubscription", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Authentication ------------- */
SEC("uprobe/nrf_access_token")
int nrf_access_token(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFAccessToken", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- NF_Discovery ------------- */
SEC("uprobe/nrf_nf_discovery")
int nrf_nf_discovery(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NRFNFDiscovery", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}