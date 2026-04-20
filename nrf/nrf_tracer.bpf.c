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


/* -------------- TODO -------------- */
/* NF_Management */

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

/* -------------- TODO -------------- */
/* Authentication */


/* -------------- TODO -------------- */
/* NF_Discovery */