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


/* ------------- AM Policy ------------- */
// AM Post
SEC("uprobe/pcf_am_post")
int pcf_am_post(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFAMPost", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// AM Update
SEC("uprobe/pcf_am_update")
int pcf_am_update(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFAMUpdate", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// AM Get
SEC("uprobe/pcf_am_get")
int pcf_am_get(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFAMGet", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// AM Delete
SEC("uprobe/pcf_am_delete")
int pcf_am_delete(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFAMDelete", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- BDT Policy ------------- */
// BDT Get
SEC("uprobe/pcf_bdt_get")
int pcf_bdt_get(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFBDTGet", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// BDT Update
SEC("uprobe/pcf_bdt_update")
int pcf_bdt_update(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFBDTUpdate", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// BDT Create
SEC("uprobe/pcf_bdt_create")
int pcf_bdt_create(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFBDTCreate", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- OAM ------------- */
// OAM Get AM Policy Request
SEC("uprobe/pcf_oam_get_am")
int pcf_oam_get_am(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFOAMGetAM", 11);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- Policy Authorization ------------- */
// Post App Session Context
SEC("uprobe/pcf_post_app_sess_ctx")
int pcf_post_app_sess_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFPostAppSessCtx", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get App Session Context
SEC("uprobe/pcf_get_app_sess_ctx")
int pcf_get_app_sess_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFGetAppSessCtx", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Delete App Session Context
SEC("uprobe/pcf_delete_app_sess_ctx")
int pcf_delete_app_sess_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFDeleteAppSessCtx", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Modify App Session Context
SEC("uprobe/pcf_mod_app_sess_ctx")
int pcf_mod_app_sess_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFModifyAppSessCtx", 19);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Delete Event Subscription Context
SEC("uprobe/pcf_del_evnts_sub_ctx")
int pcf_del_evnts_sub_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFDeleteEventSubscriptionCtx", 27);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update Event Subscription Context
SEC("uprobe/pcf_upd_evnts_sub_ctx")
int pcf_upd_evnts_sub_ctx(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFUpdateEventSubscriptionCtx", 27);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------- SM Policy ------------- */
// Create SM Policy
SEC("uprobe/pcf_create_sm_policy")
int pcf_create_sm_policy(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFCreateSMPolicy", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get SM Policy
SEC("uprobe/pcf_get_sm_policy")
int pcf_get_sm_policy(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFGetSMPolicy", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Update SM Policy
SEC("uprobe/pcf_update_sm_policy")
int pcf_update_sm_policy(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFUpdateSMPolicy", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Delete SM Policy
SEC("uprobe/pcf_delete_sm_policy")
int pcf_delete_sm_policy(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "PCF", 4);
    __builtin_memcpy(e->api, "PCFDeleteSMPolicy", 17);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

