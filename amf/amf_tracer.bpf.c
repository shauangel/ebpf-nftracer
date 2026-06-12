// amf_tracer.bpf.c
//
// Probe class:
//
//  UPROBES — attached by the loader to specific AMF Go symbols.
//            Fire only for the target PID; no extra cgroup filter needed.
//            Emit EVT_API_CALL events.

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../events.h"

char LICENSE[] SEC("license") = "GPL";

/* ── Maps ──────────────────────────────────────────────────────────────── */

/* Ring buffer — all events flow here */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   /* 16 MB */
} events SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────────────── */

/* Reserve a ring-buffer slot and fill common fields */
static __always_inline struct event *new_event(__u8 type)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    e->type = type;
    e->ts   = bpf_ktime_get_ns();
    __u64 pt = bpf_get_current_pid_tgid();
    e->pid  = (__u32)(pt >> 32);
    e->tid  = (__u32)pt;
    e->cid  = bpf_get_current_cgroup_id();
    __builtin_memcpy(e->nf, "AMF", 4);
    return e;
}

/* ═══════════════════════════════════════════════════════════════════════
 * AMF API uprobes
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── Subscription ───────────────────────────────────────────────────────── */

SEC("uprobe/amf_stat_ch_sub")
int amf_stat_ch_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFStatusChangeSubscribe", 24);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_stat_ch_unsub")
int amf_stat_ch_unsub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFStatusChangeUnSubscribe", 26);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_stat_ch_mod_sub")
int amf_stat_ch_mod_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFStatusChangeSubscribeModify", 30);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── UE Context ─────────────────────────────────────────────────────────── */

SEC("uprobe/amf_ue_create")
int amf_ue_create(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFUECreate", 11);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ue_assign_ebi")
int amf_ue_assign_ebi(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFUEAssignEBI", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ue_release")
int amf_ue_release(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFUERelease", 12);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ue_transfer")
int amf_ue_transfer(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFUETransfer", 13);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ue_reg_stat_update")
int amf_ue_reg_stat_update(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFUERegistrationStatusUpdate", 29);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Callback ───────────────────────────────────────────────────────────── */

SEC("uprobe/amf_n1msg_notify")
int amf_n1msg_notify(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFN1MessageNotify", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sm_notify")
int amf_sm_notify(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFSMContextStatusNotify", 24);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_am_update_notify")
int amf_am_update_notify(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFAMUpdateNotify", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_am_terminate_notify")
int amf_am_terminate_notify(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFAMTerminateNotify", 20);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Event Exposure ─────────────────────────────────────────────────────── */

SEC("uprobe/amf_create_event_sub")
int amf_create_event_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFCreateEventSubscription", 26);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_modify_event_sub")
int amf_modify_event_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFModifyEventSubscription", 26);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_delete_event_sub")
int amf_delete_event_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFDeleteEventSubscription", 26);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── N1N2 Message ───────────────────────────────────────────────────────── */

SEC("uprobe/amf_n1n2msg_transfer")
int amf_n1n2msg_transfer(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFN1N2MessageTransfer", 22);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_n1n2msg_sub")
int amf_n1n2msg_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFN1N2MessageSubscribe", 23);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_n1n2msg_unsub")
int amf_n1n2msg_unsub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFN1N2MessageUnsubscribe", 25);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_n1n2msg_stat")
int amf_n1n2msg_stat(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFN1N2MessageTransferStatus", 28);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Location / Domain / OAM ────────────────────────────────────────────── */

SEC("uprobe/amf_loc_info")
int amf_loc_info(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFLocationInfo", 15);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_domain_sel_info")
int amf_domain_sel_info(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFDomainSelectionInfo", 22);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_oam_ue_context")
int amf_oam_ue_context(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AMFOAMUEContext", 15);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
