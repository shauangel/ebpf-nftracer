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
/* Subscription */
SEC("uprobe/amf_stat_ch_sub")
int amf_stat_ch_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFStatusChangeSubscribe", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_stat_ch_unsub")
int amf_stat_ch_unsub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFStatusChangeUnSubscribe", 26);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_stat_ch_mod_sub")
int amf_stat_ch_mod_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFStatusChangeSubscribeModify", 28);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------- TODO -------------- */
/* UE_Context */


/* -------------- TODO -------------- */
/* Callback */


/* -------------- TODO -------------- */
/* Event_Exposure */



/* -------------- TODO -------------- */
/* N1N2Message */



/* -------------- TODO -------------- */
/* Mt */


/* -------------- TODO -------------- */
/* OAM */


/* -------------- TODO -------------- */
/* Location_Info */