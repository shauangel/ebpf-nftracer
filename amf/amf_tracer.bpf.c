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


/* ------------- Subscription ------------- */
// Status Change Subscribe probe
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

// Status Change Unsubscribe probe
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

// Status Change Subscribe Modify probe
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


/* ------------- UE_Context ------------- */
// UE Create probe
SEC("uprobe/amf_ue_create")
int amf_ue_create(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFUECreate", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// UE Assign EBI probe
SEC("uprobe/amf_ue_assign_ebi")
int amf_ue_assign_ebi(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFUEAssignEBI", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// UE Release probe
SEC("uprobe/amf_ue_release")
int amf_ue_release(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFUERelease", 12);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// UE Transfer probe
SEC("uprobe/amf_ue_transfer")
int amf_ue_transfer(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFUETransfer", 13);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// UE Registration Status Update probe
SEC("uprobe/amf_ue_reg_stat_update")
int amf_ue_reg_stat_update(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFUERegistrationStatusUpdate", 27);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Callback ------------- */
// N1 Message Notify probe
SEC("uprobe/amf_n1msg_notify")
int amf_n1msg_notify(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFN1MessageNotify", 18);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SM Context Status Notify probe
SEC("uprobe/amf_sm_notify")
int amf_sm_notify(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFSMContextStatusNotify", 23);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// AMF Status Change Subscribe Modify Notify probe
SEC("uprobe/amf_am_update_notify")
int amf_am_update_notify(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFAMUpdateNotify", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// AMF Status Change Subscribe Terminate Notify probe
SEC("uprobe/amf_am_terminate_notify")
int amf_am_terminate_notify(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFAMTerminateNotify", 20);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Event_Exposure ------------- */
// Create Event Subscription probe
SEC("uprobe/amf_create_event_sub")
int amf_create_event_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFCreateEventSubscription", 26);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Modify Event Subscription probe
SEC("uprobe/amf_modify_event_sub")
int amf_modify_event_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFModifyEventSubscription", 26);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Delete Event Subscription probe
SEC("uprobe/amf_delete_event_sub")
int amf_delete_event_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFDeleteEventSubscription", 26);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------- TODO -------------- */
/* ------------- N1N2Message ------------- */
// N1N2 Message Transfer probe
SEC("uprobe/amf_n1n2msg_transfer")
int amf_n1n2msg_transfer(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFN1N2MessageTransfer", 22);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// N1N2 Message Subscribe probe
SEC("uprobe/amf_n1n2msg_sub")
int amf_n1n2msg_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFN1N2MessageSubscribe", 23);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// N1N2 Message Unsubscribe probe
SEC("uprobe/amf_n1n2msg_unsub")
int amf_n1n2msg_unsub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFN1N2MessageUnsubscribe", 25);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// N1N2 Message Transfer Status probe
SEC("uprobe/amf_n1n2msg_stat")
int amf_n1n2msg_stat(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFN1N2MessageTransferStatus", 28);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Mt ------------- */
// Provide MT Location Info probe
SEC("uprobe/amf_domain_sel_info")
int amf_domain_sel_info(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFDomainSelectionInfo", 22);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- OAM ------------- */
// Provide OAM UE Context probe
SEC("uprobe/amf_oam_ue_context")
int amf_oam_ue_context(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFOAMUEContext", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------- Location_Info -------------- */
// Location Info probe
SEC("uprobe/amf_loc_info")
int amf_loc_info(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "AMF", 4);
    __builtin_memcpy(e->api, "AMFLocationInfo", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}