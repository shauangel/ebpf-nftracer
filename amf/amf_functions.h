#ifndef AMF_FUNCTIONS_H
#define AMF_FUNCTIONS_H

#include "../common.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Threat-aware AMF FSM uprobe targets — one attach_target[] group per FSM
 * node, verified against bin/amf; see amf/verified_attach_points.txt.
 * States that add no *new* symbol (their only hooks are reused from an
 * earlier group) have no array here — see the comment at their would-be
 * declaration site in amf_functions.c.
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── Part 1 — Normal-Path States ──────────────────────────────────────── */

extern struct attach_target reg_received_funcs[];            /* 01 */
extern struct attach_target context_lookup_funcs[];           /* 02 */
extern struct attach_target identity_pending_funcs[];         /* 03 */
extern struct attach_target auth_vector_pending_funcs[];      /* 04 */
extern struct attach_target nas_authenticating_funcs[];       /* 05 */
extern struct attach_target nas_security_pending_funcs[];     /* 06 */
extern struct attach_target udm_registering_funcs[];          /* 07 */
extern struct attach_target subscription_loading_funcs[];     /* 08 */
extern struct attach_target policy_associating_funcs[];       /* 09 */
extern struct attach_target ue_context_ready_funcs[];         /* 10 */
extern struct attach_target sm_context_pending_funcs[];       /* 11 */
extern struct attach_target initial_context_setup_funcs[];    /* 12 */
extern struct attach_target registered_connected_funcs[];     /* 13 */

extern int reg_received_funcs_cnt;
extern int context_lookup_funcs_cnt;
extern int identity_pending_funcs_cnt;
extern int auth_vector_pending_funcs_cnt;
extern int nas_authenticating_funcs_cnt;
extern int nas_security_pending_funcs_cnt;
extern int udm_registering_funcs_cnt;
extern int subscription_loading_funcs_cnt;
extern int policy_associating_funcs_cnt;
extern int ue_context_ready_funcs_cnt;
extern int sm_context_pending_funcs_cnt;
extern int initial_context_setup_funcs_cnt;
extern int registered_connected_funcs_cnt;

/* ── Part 2 — Failure / Threat States ─────────────────────────────────── */
/* 16 REPLAY_SUSPECTED and 21 PDU_SESSION_REJECTED have no array: both
 * reuse a probe already declared above (state 05 and state 11
 * respectively) — see amf_functions.c. */

extern struct attach_target reg_rejected_funcs[];             /* 14 */
extern struct attach_target auth_failed_funcs[];              /* 15 */
extern struct attach_target security_failed_funcs[];          /* 17 */
extern struct attach_target security_policy_violation_funcs[];/* 18 */
extern struct attach_target nf_timeout_funcs[];                /* 19 */
extern struct attach_target slice_rejected_funcs[];            /* 20 */
extern struct attach_target context_setup_failed_funcs[];      /* 22 */
extern struct attach_target cleanup_required_funcs[];          /* 23 */

extern int reg_rejected_funcs_cnt;
extern int auth_failed_funcs_cnt;
extern int security_failed_funcs_cnt;
extern int security_policy_violation_funcs_cnt;
extern int nf_timeout_funcs_cnt;
extern int slice_rejected_funcs_cnt;
extern int context_setup_failed_funcs_cnt;
extern int cleanup_required_funcs_cnt;

/* ── Part 3 — Supplementary / Edge-only hooks ─────────────────────────── */

extern struct attach_target fsm_edge_funcs[];
extern int fsm_edge_funcs_cnt;

/* ═══════════════════════════════════════════════════════════════════════
 * NOT part of the 23-state threat-aware FSM (internal/sbi/processor.*
 * SBI-service callbacks; see amf/missing_attach_points.txt). Corresponding
 * uprobe programs are #if 0'd out in amf_tracer.bpf.c — keep these extern
 * declarations disabled to match, or amf_loader.c's attach_programs() calls
 * will fail to find the probe sections.
extern struct attach_target sub_funcs[];
extern struct attach_target ue_ctx_funcs[];
extern struct attach_target callback_funcs[];
extern struct attach_target evnt_funcs[];
extern struct attach_target n1n2msg_funcs[];
extern struct attach_target other_funcs[];
extern int sub_funcs_cnt;
extern int ue_ctx_funcs_cnt;
extern int callback_funcs_cnt;
extern int evnt_funcs_cnt;
extern int n1n2msg_funcs_cnt;
extern int other_funcs_cnt;
 */

#endif // AMF_FUNCTIONS_H
