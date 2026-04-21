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


/* ------------- Association ------------- */
// Associated with UPF probe
SEC("uprobe/smf_asso_with_upf")
int smf_asso_with_upf(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFAssociatedWithUPF", 20);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Release all resources of UPF probe
SEC("uprobe/smf_release_all_upf")
int smf_release_all_upf(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFReleaseAllUPF", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Charging Trigger ------------- */
// Create Charging Session probe
SEC("uprobe/smf_create_chg_session")
int smf_create_chg_session(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFCreateChgSession", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update Charging Session probe
SEC("uprobe/smf_update_chg_session")
int smf_update_chg_session(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFUpdateChgSession", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Release Charging Session probe
SEC("uprobe/smf_release_chg_session")
int smf_release_chg_session(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFReleaseChgSession", 20);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Report Usage and Update Quota probe
SEC("uprobe/smf_chg_usage_quota")
int smf_chg_usage_quota(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFChgUsageQuota", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Datapath ------------- */
// Activate UPF Session probe
SEC("uprobe/smf_act_upf_session")
int smf_act_upf_session(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFActivateUPFSession", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Query Report probe
SEC("uprobe/smf_query_report")
int smf_query_report(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFQueryReport", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Establish Handler probe
SEC("uprobe/smf_est_handler")
int smf_est_handler(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFEstablishHandler", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Release Tunnel probe
SEC("uprobe/smf_release_tunnel")
int smf_release_tunnel(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFReleaseTunnel", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Release DC Tunnel probe
SEC("uprobe/smf_release_dc_tunnel")
int smf_release_dc_tunnel(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFReleaseDCTunnel", 18);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- OAM ------------- */
// OAM Get UE PDU Session Info probe
SEC("uprobe/smf_oam_get_ue_pdu")
int smf_oam_get_ue_pdu(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFOAMGetUEPDU", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// OAM Get SMF Info probe
SEC("uprobe/smf_oam_get_smf_info")
int smf_oam_get_smf_info(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFOAMGetSMFInfo", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- PDU Session API ------------- */
// PDU Session SM Context Create probe
SEC("uprobe/smf_pdu_sm_create")
int smf_pdu_sm_create(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFPDUSMCreate", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// PDU Session SM Context Update probe
SEC("uprobe/smf_pdu_sm_update")
int smf_pdu_sm_update(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFPDUSMUpdate", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// PDU Session SM Context Release probe
SEC("uprobe/smf_pdu_sm_release")
int smf_pdu_sm_release(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFPDUSMRelease", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- ULCL Procedure ------------- */
// Establish PSA2
SEC("uprobe/smf_establish_psa2")
int smf_establish_psa2(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFEstablishPSA2", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Establish ULCL
SEC("uprobe/smf_establish_ulcl")
int smf_establish_ulcl(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFEstablishULCL", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update PSA2 Downlink
SEC("uprobe/smf_update_psa2_dl")
int smf_update_psa2_dl(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFUpdatePSA2DL", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Establish RAN Tunnel
SEC("uprobe/smf_establish_ran_tunnel")
int smf_establish_ran_tunnel(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFEstablishRANTunnel", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update RAN and IUPF Uplink
SEC("uprobe/smf_update_ran_iupf_ul")
int smf_update_ran_iupf_ul(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "SMF", 3);
    __builtin_memcpy(e->api, "SMFUpdateRANIUPFUL", 18);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

