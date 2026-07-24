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

/* Threat-aware AMF FSM as two BPF_MAP_TYPE_HASH maps (sm_nodes, sm_edges)
 * + in-kernel lookup helpers (sm_node_lookup, sm_transition_lookup).
 * Populated at runtime by the userspace loader -- see sm_map.c. */
#include "sm_map.c"

char LICENSE[] SEC("license") = "GPL";

/* ── Maps ──────────────────────────────────────────────────────────────── */

/* Ring buffer — all events flow here */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   /* 16 MB */
} events SEC(".maps");

/* Single-entry array: the AMF container's cgroupv2 ID.
 * Written by the loader immediately after skeleton load. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} amf_cgroup_map SEC(".maps");

/* Scratch: save connect() entry args across the syscall boundary */
struct _connect_args { __u64 fd; struct sockaddr *addr; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);           /* tid */
    __type(value, struct _connect_args);
} connect_scratch SEC(".maps");

/* Scratch: save accept4() entry args across the syscall boundary */
struct _accept_args { __u64 fd; struct sockaddr *addr; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, struct _accept_args);
} accept_scratch SEC(".maps");

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

/* True if calling process is in the AMF container cgroup */
static __always_inline int is_amf_cgroup(void)
{
    __u32 key = 0;
    __u64 *stored = bpf_map_lookup_elem(&amf_cgroup_map, &key);
    if (!stored || *stored == 0)
        return 0;
    return bpf_get_current_cgroup_id() == *stored;
}

/* Read IPv4 sockaddr fields into an event (connect / accept) */
static __always_inline void read_sockaddr_in(struct event *e,
                                              struct sockaddr *sa)
{
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
    if (family != 2 /* AF_INET */)
        return;

    e->af = 2;
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), sa);
    e->dest_ip   = sin.sin_addr.s_addr;
    e->dest_port = __builtin_bswap16(sin.sin_port);
}


/* ═══════════════════════════════════════════════════════════════════════
 * Threat-aware AMF FSM uprobes — one handler per prog_name declared in
 * amf_functions.c, grouped by FSM node exactly like those attach_target[]
 * arrays. func_name verified against bin/amf; see
 * amf/verified_attach_points.txt. Each handler just records that the
 * symbol fired (EVT_API_CALL, e->api = "<STATE>:<Symbol>") -- richer
 * per-arg/return handling (e.g. sm_transition_lookup() validation against
 * sm_edges) is future work, not wired in here yet.
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── 01 REG_RECEIVED ───────────────────────────────────────────────────── */

SEC("uprobe/amf_ngap_ue_msg")
int amf_ngap_ue_msg(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "REG:NGAPInitialUEMsg", 20);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_handle_nas")
int amf_handle_nas(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "REG:HandleNAS", 13);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 02 CONTEXT_LOOKUP ─────────────────────────────────────────────────── */

SEC("uprobe/amf_ctx_lookup")
int amf_ctx_lookup(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "CTXLOOKUP:XferOldAmf", 20);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ctx_xfer")
int amf_ctx_xfer(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "CTXLOOKUP:XferReq", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 03 IDENTITY_PENDING ───────────────────────────────────────────────── */

SEC("uprobe/amf_id_req")
int amf_id_req(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "IDPENDING:SendReq", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_id_resp")
int amf_id_resp(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "IDPENDING:HandleResp", 20);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 04 AUTH_VECTOR_PENDING ────────────────────────────────────────────── */

SEC("uprobe/amf_auth_proc")
int amf_auth_proc(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AVPENDING:AuthProc", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ausf_auth")
int amf_ausf_auth(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AVPENDING:AusfAuth", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 05 NAS_AUTHENTICATING ─────────────────────────────────────────────── */

SEC("uprobe/amf_auth_req")
int amf_auth_req(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NASAUTH:SendReq", 15);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_auth_resp")
int amf_auth_resp(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NASAUTH:HandleResp", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_auth_fail")
int amf_auth_fail(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NASAUTH:HandleFail", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 06 NAS_SECURITY_PENDING ───────────────────────────────────────────── */

SEC("uprobe/amf_sec_mode")
int amf_sec_mode(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECPENDING:Mode", 15);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sec_cmd")
int amf_sec_cmd(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECPENDING:Cmd", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sec_cmplt")
int amf_sec_cmplt(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECPENDING:Complete", 19);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sec_reject")
int amf_sec_reject(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECPENDING:Reject", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 07 UDM_REGISTERING ────────────────────────────────────────────────── */

SEC("uprobe/amf_udm_comm")
int amf_udm_comm(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "UDMREG:Communicate", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_udm_uecm")
int amf_udm_uecm(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "UDMREG:UeCmReg", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 08 SUBSCRIPTION_LOADING ───────────────────────────────────────────── */

SEC("uprobe/amf_sdm_amdata")
int amf_sdm_amdata(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SUBLOAD:AmData", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sdm_smfsel")
int amf_sdm_smfsel(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SUBLOAD:SmfSel", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sdm_uectx")
int amf_sdm_uectx(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SUBLOAD:UeCtx", 13);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_sdm_sub")
int amf_sdm_sub(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SUBLOAD:Sub", 11);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 09 POLICY_ASSOCIATING ─────────────────────────────────────────────── */

SEC("uprobe/amf_pcf_policy")
int amf_pcf_policy(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "POLICY:AmCreate", 15);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 10 UE_CONTEXT_READY ───────────────────────────────────────────────── */

SEC("uprobe/amf_reg_accept")
int amf_reg_accept(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "UECTXREADY:Accept", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 11 SM_CONTEXT_PENDING (also 21 PDU_SESSION_REJECTED reject branch) ─── */

SEC("uprobe/amf_pdu_create")
int amf_pdu_create(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SMPENDING:PduCreate", 19);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_smf_ctx_req")
int amf_smf_ctx_req(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SMPENDING:SmfCtxReq", 19);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 12 INITIAL_CONTEXT_SETUP ──────────────────────────────────────────── */

SEC("uprobe/amf_ics_req")
int amf_ics_req(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "ICS:Req", 7);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ics_resp")
int amf_ics_resp(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "ICS:RespMain", 12);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 13 REGISTERED_CONNECTED ───────────────────────────────────────────── */

SEC("uprobe/amf_registered")
int amf_registered(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "REGCONN:Registered", 18);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_reg_cmplt")
int amf_reg_cmplt(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "REGCONN:Complete", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 14 REG_REJECTED ───────────────────────────────────────────────────── */

SEC("uprobe/amf_reg_reject")
int amf_reg_reject(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "REGREJECT:Send", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 15 AUTH_FAILED (also 16 REPLAY_SUSPECTED's SynchFailure branch,
 * via amf_auth_fail from state 05) ───────────────────────────────────── */

SEC("uprobe/amf_auth_fsm")
int amf_auth_fsm(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "AUTHFAILED:FsmEvt", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 17 SECURITY_FAILED ────────────────────────────────────────────────── */

SEC("uprobe/amf_nas_decode")
int amf_nas_decode(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECFAILED:Decode", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 18 SECURITY_POLICY_VIOLATION ──────────────────────────────────────── */

SEC("uprobe/amf_sel_sec_alg")
int amf_sel_sec_alg(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SECPOLICY:SelAlg", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 19 NF_TIMEOUT ─────────────────────────────────────────────────────── */

SEC("uprobe/amf_nssf_sel")
int amf_nssf_sel(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NFTIMEOUT:NssfSel", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 20 SLICE_REJECTED ─────────────────────────────────────────────────── */

SEC("uprobe/amf_nssai_req")
int amf_nssai_req(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SLICEREJ:NssaiReq", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_5gsm_msg")
int amf_5gsm_msg(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "SLICEREJ:5gsmMsg", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 22 CONTEXT_SETUP_FAILED ───────────────────────────────────────────── */

SEC("uprobe/amf_ics_fail")
int amf_ics_fail(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "ICSFAILED:Main", 14);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 23 CLEANUP_REQUIRED ───────────────────────────────────────────────── */

SEC("uprobe/amf_remove_ue")
int amf_remove_ue(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "CLEANUP:RemoveUe", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ue_remove")
int amf_ue_remove(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "CLEANUP:UeRemove", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Part 3 — Supplementary / Edge-only hooks ──────────────────────────── */

SEC("uprobe/amf_sec_ctx_ok")
int amf_sec_ctx_ok(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "EDGE:SecCtxValid", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_ics_disp")
int amf_ics_disp(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "EDGE:IcsDispatch", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_nas_disp")
int amf_nas_disp(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "EDGE:NasDispatch", 16);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/amf_fsm_event")
int amf_fsm_event(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "EDGE:FsmSendEvent", 17);
    bpf_ringbuf_submit(e, 0);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════
 * AMF API uprobes — NOT part of the 23-state threat-aware FSM
 * (internal/sbi/processor.(*Processor).* SBI-service callbacks; see
 * amf/missing_attach_points.txt — none of these match the PDF hook points)
 * ═══════════════════════════════════════════════════════════════════════ */
#if 0

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

#endif /* AMF API uprobes not in FSM */


/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 — Socket syscall tracepoints  (new, cgroup-filtered)
 * ═══════════════════════════════════════════════════════════════════════ */

/* connect(2) — outgoing TCP connections (NRF acting as HTTP/2 client) */

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_amf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _connect_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&connect_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_amf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _connect_args *a = bpf_map_lookup_elem(&connect_scratch, &tid);
    if (!a) return 0;
    bpf_map_delete_elem(&connect_scratch, &tid);

    /* success or EINPROGRESS (-115) for non-blocking sockets */
    if (ctx->ret != 0 && ctx->ret != -115) return 0;

    struct event *e = new_event(EVT_CONNECT);
    if (!e) return 0;
    read_sockaddr_in(e, a->addr);
    e->ret = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* accept4(2) — incoming connections (NRF acting as HTTP/2 server) */

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_amf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _accept_args args = {
        .fd   = (int)ctx->args[0],
        .addr = (struct sockaddr *)ctx->args[1],
    };
    bpf_map_update_elem(&accept_scratch, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_amf_cgroup()) return 0;
    __u64 tid = (__u32)bpf_get_current_pid_tgid();
    struct _accept_args *a = bpf_map_lookup_elem(&accept_scratch, &tid);
    if (!a) return 0;
    bpf_map_delete_elem(&accept_scratch, &tid);

    if (ctx->ret < 0) return 0;   /* failed accept */

    struct event *e = new_event(EVT_ACCEPT);
    if (!e) return 0;
    if (a->addr)
        read_sockaddr_in(e, a->addr);  /* fills peer (caller) address */
    e->ret = ctx->ret;                 /* new socket fd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* write(2) — data sent by NRF (HTTP/2 frames, response bodies) */

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_amf_cgroup()) return 0;
    __u64 count = (size_t)ctx->args[2];
    if (count == 0) return 0;

    struct event *e = new_event(EVT_WRITE);
    if (!e) return 0;
    e->bytes = count;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* read(2) — data received by NRF; probe exit for the actual byte count */

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_amf_cgroup()) return 0;
    if (ctx->ret <= 0) return 0;

    struct event *e = new_event(EVT_READ);
    if (!e) return 0;
    e->bytes = (__u64)ctx->ret;
    e->ret   = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

