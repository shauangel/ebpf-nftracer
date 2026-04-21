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


/* ------------- Event Exposure ------------- */
// Create EE Subscription
SEC("uprobe/udm_create_ee_sub")
int udm_create_ee_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMCreateEESubscription", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Delete EE Subscription
SEC("uprobe/udm_delete_ee_sub")
int udm_delete_ee_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMDeleteEESubscription", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update EE Subscription
SEC("uprobe/udm_update_ee_sub")
int udm_update_ee_sub(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMUpdateEESubscription", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Generate Authentication Data ------------- */
// Confirm Authentication Data
SEC("uprobe/udm_confirm_auth_data")
int udm_confirm_auth_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMConfirmAuthenticationData", 28);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Generate Authentication Data
SEC("uprobe/udm_generate_auth_data")
int udm_generate_auth_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGenerateAuthenticationData", 29);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Parameter Provision ------------- */
// Update Procedure
SEC("uprobe/udm_para_prov_update")
int udm_para_prov_update(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMParameterProvisioningUpdate", 29);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Subscriber Data Management ------------- */
// Get AM Data
SEC("uprobe/udm_get_am_data")
int udm_get_am_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetAMData", 13);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get ID Tranfer Results
SEC("uprobe/udm_get_id_trans_rslt")
int udm_get_id_trans_rslt(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetIDTransferResults", 23);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get SUPI
SEC("uprobe/udm_get_supi")
int udm_get_supi(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetSUPI", 12);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get Shared Data
SEC("uprobe/udm_get_shared_data")
int udm_get_shared_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetSharedData", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get SM Data
SEC("uprobe/udm_get_sm_data")
int udm_get_sm_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetSMData", 13);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get NSSAI
SEC("uprobe/udm_get_nssai")
int udm_get_nssai(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetNSSAI", 13);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get SMF Selection Data
SEC("uprobe/udm_get_smf_slct_data")
int udm_get_smf_slct_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetSMFSelectionData", 23);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Subscribe to Shared Data
SEC("uprobe/udm_sub_shared_data")
int udm_sub_shared_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMSubscribeToSharedData", 25);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Subscribe
SEC("uprobe/udm_subscribe")
int udm_subscribe(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMSubscribe", 12);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Unsubscribe from Shared Data
SEC("uprobe/udm_unsub_shared_data")
int udm_unsub_shared_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMUnsubscribeFromSharedData", 28);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Unsubscribe
SEC("uprobe/udm_unsubscribe")
int udm_unsubscribe(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMUnsubscribe", 14);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Modify
SEC("uprobe/udm_modify")
int udm_modify(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMModify", 9);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Modify for Shared Data
SEC("uprobe/udm_mod_shared_data")
int udm_mod_shared_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMModifySharedData", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get Trace Data
SEC("uprobe/udm_get_trace_data")
int udm_get_trace_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetTraceData", 15);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get UE Context in SMF Data
SEC("uprobe/udm_get_ue_ctx_smf_data")
int udm_get_ue_ctx_smf_data(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetUEContextInSMFData", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- UE Context Management ------------- */
// Get AMF 3GPP Access
SEC("uprobe/udm_get_amf3gpp_access")
int udm_get_amf3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetAMF3GPPAccess", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get AMF Non-3GPP Access
SEC("uprobe/udm_get_amfnon3gpp_access")
int udm_get_amfnon3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMGetAMFNon3GPPAccess", 22);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Registration for AMF 3GPP Access
SEC("uprobe/udm_reg_amf3gpp_access")
int udm_reg_amf3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMRegisterAMF3GPPAccess", 24);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Registration for AMF Non-3GPP Access
SEC("uprobe/udm_reg_amfnon3gpp_access")
int udm_reg_amfnon3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMRegisterAMNon3GPPAccess", 27);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update AMF 3GPP Access
SEC("uprobe/udm_update_amf3gpp_access")
int udm_update_amf3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMUpdateAMF3GPPAccess", 22);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update AMF Non-3GPP Access
SEC("uprobe/udm_update_amfnon3gpp_access")
int udm_update_amfnon3gpp_access(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMUpdateAMNon3GPPAccess", 25);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Deregister SMF Registration
SEC("uprobe/udm_dereg_smf_reg")
int udm_dereg_smf_reg(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMDeregisterSMFRegistration", 28);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Register SMF Registration
SEC("uprobe/udm_reg_smf_reg")
int udm_reg_smf_reg(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "UDM", 4);
    __builtin_memcpy(e->api, "UDMRegisterSMFRegistration", 26);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
