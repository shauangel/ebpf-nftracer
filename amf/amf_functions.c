#include "amf_functions.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Threat-aware AMF FSM uprobe targets — grouped one attach_target[] per
 * FSM node, func_name verified against bin/amf (see
 * amf/verified_attach_points.txt). prog_name kept <=15 chars.
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── Part 1 — Normal-Path States ──────────────────────────────────────── */

/* 01 REG_RECEIVED */
struct attach_target reg_received_funcs[] = {
    {
        .prog_name = "amf_ngap_ue_msg",
        .func_name = "github.com/free5gc/amf/internal/ngap.handleInitialUEMessageMain",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_handle_nas",
        .func_name = "github.com/free5gc/amf/internal/nas.HandleNAS",
        .retprobe = false,
        .link = NULL,
    },
};
int reg_received_funcs_cnt = sizeof(reg_received_funcs) / sizeof(reg_received_funcs[0]);

/* 02 CONTEXT_LOOKUP */
struct attach_target context_lookup_funcs[] = {
    {
        .prog_name = "amf_ctx_lookup",
        .func_name = "github.com/free5gc/amf/internal/gmm.contextTransferFromOldAmf",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ctx_xfer",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*namfService).UEContextTransferRequest",
        .retprobe = true,
        .link = NULL,
    },
};
int context_lookup_funcs_cnt = sizeof(context_lookup_funcs) / sizeof(context_lookup_funcs[0]);

/* 03 IDENTITY_PENDING */
struct attach_target identity_pending_funcs[] = {
    {
        .prog_name = "amf_id_req",
        .func_name = "github.com/free5gc/amf/internal/gmm/message.SendIdentityRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_id_resp",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleIdentityResponse",
        .retprobe = false,
        .link = NULL,
    },
};
int identity_pending_funcs_cnt = sizeof(identity_pending_funcs) / sizeof(identity_pending_funcs[0]);

/* 04 AUTH_VECTOR_PENDING */
struct attach_target auth_vector_pending_funcs[] = {
    {
        .prog_name = "amf_auth_proc",
        .func_name = "github.com/free5gc/amf/internal/gmm.AuthenticationProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ausf_auth",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nausfService).SendUEAuthenticationAuthenticateRequest",
        .retprobe = true,
        .link = NULL,
    },
};
int auth_vector_pending_funcs_cnt = sizeof(auth_vector_pending_funcs) / sizeof(auth_vector_pending_funcs[0]);

/* 05 NAS_AUTHENTICATING */
struct attach_target nas_authenticating_funcs[] = {
    {
        .prog_name = "amf_auth_req",
        .func_name = "github.com/free5gc/amf/internal/gmm/message.SendAuthenticationRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_auth_resp",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleAuthenticationResponse",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_auth_fail",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleAuthenticationFailure",
        .retprobe = false,
        .link = NULL,
    },
};
int nas_authenticating_funcs_cnt = sizeof(nas_authenticating_funcs) / sizeof(nas_authenticating_funcs[0]);

/* 06 NAS_SECURITY_PENDING */
struct attach_target nas_security_pending_funcs[] = {
    {
        .prog_name = "amf_sec_mode",
        .func_name = "github.com/free5gc/amf/internal/gmm.SecurityMode",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sec_cmd",
        .func_name = "github.com/free5gc/amf/internal/gmm/message.SendSecurityModeCommand",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sec_cmplt",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleSecurityModeComplete",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sec_reject",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleSecurityModeReject",
        .retprobe = false,
        .link = NULL,
    },
};
int nas_security_pending_funcs_cnt = sizeof(nas_security_pending_funcs) / sizeof(nas_security_pending_funcs[0]);

/* 07 UDM_REGISTERING */
struct attach_target udm_registering_funcs[] = {
    {
        .prog_name = "amf_udm_comm",
        .func_name = "github.com/free5gc/amf/internal/gmm.communicateWithUDM",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_udm_uecm",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nudmService).UeCmRegistration",
        .retprobe = true,
        .link = NULL,
    },
};
int udm_registering_funcs_cnt = sizeof(udm_registering_funcs) / sizeof(udm_registering_funcs[0]);

/* 08 SUBSCRIPTION_LOADING */
struct attach_target subscription_loading_funcs[] = {
    {
        .prog_name = "amf_sdm_amdata",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nudmService).SDMGetAmData",
        .retprobe = true,
        .link = NULL,
    },
    {
        .prog_name = "amf_sdm_smfsel",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nudmService).SDMGetSmfSelectData",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sdm_uectx",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nudmService).SDMGetUeContextInSmfData",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sdm_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nudmService).SDMSubscribe",
        .retprobe = false,
        .link = NULL,
    },
};
int subscription_loading_funcs_cnt = sizeof(subscription_loading_funcs) / sizeof(subscription_loading_funcs[0]);

/* 09 POLICY_ASSOCIATING */
struct attach_target policy_associating_funcs[] = {
    {
        .prog_name = "amf_pcf_policy",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*npcfService).AMPolicyControlCreate",
        .retprobe = true,
        .link = NULL,
    },
};
int policy_associating_funcs_cnt = sizeof(policy_associating_funcs) / sizeof(policy_associating_funcs[0]);

/* 10 UE_CONTEXT_READY */
struct attach_target ue_context_ready_funcs[] = {
    {
        .prog_name = "amf_reg_accept",
        .func_name = "github.com/free5gc/amf/internal/gmm/message.SendRegistrationAccept",
        .retprobe = false,
        .link = NULL,
    },
};
int ue_context_ready_funcs_cnt = sizeof(ue_context_ready_funcs) / sizeof(ue_context_ready_funcs[0]);

/* 11 SM_CONTEXT_PENDING (also covers 21 PDU_SESSION_REJECTED's reject
 * branch of CreatePDUSession -- same symbol, distinguish via args/return) */
struct attach_target sm_context_pending_funcs[] = {
    {
        .prog_name = "amf_pdu_create",
        .func_name = "github.com/free5gc/amf/internal/gmm.CreatePDUSession",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_smf_ctx_req",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nsmfService).SendCreateSmContextRequest",
        .retprobe = true,
        .link = NULL,
    },
};
int sm_context_pending_funcs_cnt = sizeof(sm_context_pending_funcs) / sizeof(sm_context_pending_funcs[0]);

/* 12 INITIAL_CONTEXT_SETUP */
struct attach_target initial_context_setup_funcs[] = {
    {
        .prog_name = "amf_ics_req",
        .func_name = "github.com/free5gc/amf/internal/ngap/message.SendInitialContextSetupRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ics_resp",
        .func_name = "github.com/free5gc/amf/internal/ngap.handleInitialContextSetupResponseMain",
        .retprobe = false,
        .link = NULL,
    },
};
int initial_context_setup_funcs_cnt = sizeof(initial_context_setup_funcs) / sizeof(initial_context_setup_funcs[0]);

/* 13 REGISTERED_CONNECTED */
struct attach_target registered_connected_funcs[] = {
    {
        .prog_name = "amf_registered",
        .func_name = "github.com/free5gc/amf/internal/gmm.Registered",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_reg_cmplt",
        .func_name = "github.com/free5gc/amf/internal/gmm.HandleRegistrationComplete",
        .retprobe = false,
        .link = NULL,
    },
};
int registered_connected_funcs_cnt = sizeof(registered_connected_funcs) / sizeof(registered_connected_funcs[0]);

/* ── Part 2 — Failure / Threat States ─────────────────────────────────── */

/* 14 REG_REJECTED */
struct attach_target reg_rejected_funcs[] = {
    {
        .prog_name = "amf_reg_reject",
        .func_name = "github.com/free5gc/amf/internal/gmm/message.SendRegistrationReject",
        .retprobe = false,
        .link = NULL,
    },
};
int reg_rejected_funcs_cnt = sizeof(reg_rejected_funcs) / sizeof(reg_rejected_funcs[0]);

/* 15 AUTH_FAILED (also covers 16 REPLAY_SUSPECTED's SynchFailure branch,
 * which lives in HandleAuthenticationFailure -- reused from state 05, not
 * re-declared here. ue.MacFailed itself is a struct field, not hookable) */
struct attach_target auth_failed_funcs[] = {
    {
        .prog_name = "amf_auth_fsm",
        .func_name = "github.com/free5gc/amf/internal/gmm.Authentication",
        .retprobe = false,
        .link = NULL,
    },
};
int auth_failed_funcs_cnt = sizeof(auth_failed_funcs) / sizeof(auth_failed_funcs[0]);

/* 17 SECURITY_FAILED (HandleSecurityModeReject / HandleSecurityModeComplete
 * reused from state 06, not re-declared here) */
struct attach_target security_failed_funcs[] = {
    {
        .prog_name = "amf_nas_decode",
        .func_name = "github.com/free5gc/amf/internal/nas/nas_security.Decode",
        .retprobe = false,
        .link = NULL,
    },
};
int security_failed_funcs_cnt = sizeof(security_failed_funcs) / sizeof(security_failed_funcs[0]);

/* 18 SECURITY_POLICY_VIOLATION */
struct attach_target security_policy_violation_funcs[] = {
    {
        .prog_name = "amf_sel_sec_alg",
        .func_name = "github.com/free5gc/amf/internal/context.(*AmfUe).SelectSecurityAlg",
        .retprobe = false,
        .link = NULL,
    },
};
int security_policy_violation_funcs_cnt = sizeof(security_policy_violation_funcs) / sizeof(security_policy_violation_funcs[0]);

/* 19 NF_TIMEOUT (also reuses the uretprobes already declared in states
 * 04/07/08/09/11 -- classify their returned error as a timeout) */
struct attach_target nf_timeout_funcs[] = {
    {
        .prog_name = "amf_nssf_sel",
        .func_name = "github.com/free5gc/amf/internal/sbi/consumer.(*nssfService).NSSelectionGetForRegistration",
        .retprobe = true,
        .link = NULL,
    },
};
int nf_timeout_funcs_cnt = sizeof(nf_timeout_funcs) / sizeof(nf_timeout_funcs[0]);

/* 20 SLICE_REJECTED (NSSelectionGetForRegistration reused from state 19,
 * not re-declared here) */
struct attach_target slice_rejected_funcs[] = {
    {
        .prog_name = "amf_nssai_req",
        .func_name = "github.com/free5gc/amf/internal/gmm.handleRequestedNssai",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_5gsm_msg",
        .func_name = "github.com/free5gc/amf/internal/gmm.transport5GSMMessage",
        .retprobe = false,
        .link = NULL,
    },
};
int slice_rejected_funcs_cnt = sizeof(slice_rejected_funcs) / sizeof(slice_rejected_funcs[0]);

/* 21 PDU_SESSION_REJECTED -- no array: reject branch of CreatePDUSession,
 * same symbol as state 11's amf_pdu_create (sm_context_pending_funcs). */

/* 22 CONTEXT_SETUP_FAILED */
struct attach_target context_setup_failed_funcs[] = {
    {
        .prog_name = "amf_ics_fail",
        .func_name = "github.com/free5gc/amf/internal/ngap.handleInitialContextSetupFailureMain",
        .retprobe = false,
        .link = NULL,
    },
};
int context_setup_failed_funcs_cnt = sizeof(context_setup_failed_funcs) / sizeof(context_setup_failed_funcs[0]);

/* 23 CLEANUP_REQUIRED */
struct attach_target cleanup_required_funcs[] = {
    {
        .prog_name = "amf_remove_ue",
        .func_name = "github.com/free5gc/amf/internal/gmm/common.RemoveAmfUe",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ue_remove",
        .func_name = "github.com/free5gc/amf/internal/context.(*AmfUe).Remove",
        .retprobe = false,
        .link = NULL,
    },
};
int cleanup_required_funcs_cnt = sizeof(cleanup_required_funcs) / sizeof(cleanup_required_funcs[0]);

/* ── Part 3 — Supplementary / Edge-only hooks ─────────────────────────── */

struct attach_target fsm_edge_funcs[] = {
    {
        .prog_name = "amf_sec_ctx_ok",
        .func_name = "github.com/free5gc/amf/internal/context.(*AmfUe).SecurityContextIsValid",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ics_disp",
        .func_name = "github.com/free5gc/amf/internal/ngap.handlerInitialContextSetupResponse",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_nas_disp",
        .func_name = "github.com/free5gc/amf/internal/nas.Dispatch",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_fsm_event",
        .func_name = "github.com/free5gc/util/fsm.(*FSM).SendEvent",
        .retprobe = false,
        .link = NULL,
    },
};
int fsm_edge_funcs_cnt = sizeof(fsm_edge_funcs) / sizeof(fsm_edge_funcs[0]);


/* ═══════════════════════════════════════════════════════════════════════
 * NOT part of the 23-state threat-aware FSM (internal/sbi/processor.*
 * SBI-service callbacks; see amf/missing_attach_points.txt). Corresponding
 * uprobe programs are #if 0'd out in amf_tracer.bpf.c and the extern
 * declarations are commented out in amf_functions.h — kept disabled here
 * to match, and the attach/detach calls in amf_loader.c are #if 0'd too. */
#if 0

/* ------ Subscription API ------ */
struct attach_target sub_funcs[] = {
    {
        .prog_name = "amf_stat_ch_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeSubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_stat_ch_unsub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeUnSubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_stat_ch_mod_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeSubscribeModifyProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int sub_funcs_cnt = sizeof(sub_funcs) / sizeof(sub_funcs[0]);


/* ------ UE-Context API ------ */
struct attach_target ue_ctx_funcs[] = {
    {
        .prog_name = "amf_ue_create",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).CreateUEContextProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ue_assign_ebi",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AssignEbiDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ue_release",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).ReleaseUEContextProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ue_transfer",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).UEContextTransferProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_ue_reg_stat_update",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).RegistrationStatusUpdateProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int ue_ctx_funcs_cnt = sizeof(ue_ctx_funcs) / sizeof(ue_ctx_funcs[0]);

/* ------ Callback API ------ */
struct attach_target callback_funcs[] = {
    {
        .prog_name = "amf_n1msg_notify",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).N1MessageNotifyProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_sm_notify",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).SmContextStatusNotifyProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_am_update_notify",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AmPolicyControlUpdateNotifyUpdateProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_am_terminate_notify",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AmPolicyControlUpdateNotifyTerminateProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int callback_funcs_cnt = sizeof(callback_funcs) / sizeof(callback_funcs[0]);

/* ------ Event Exposure API ------ */
struct attach_target evnt_funcs[] = {
    {
        .prog_name = "amf_create_event_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).CreateAMFEventSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_modify_event_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).ModifyAMFEventSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_delete_event_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).DeleteAMFEventSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int evnt_funcs_cnt = sizeof(evnt_funcs) / sizeof(evnt_funcs[0]);

/* ------ N1N2 Message API ------ */
struct attach_target n1n2msg_funcs[] = {
    {
        .prog_name = "amf_n1n2msg_transfer",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).N1N2MessageTransferProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_n1n2msg_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).N1N2MessageSubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_n1n2msg_unsub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).N1N2MessageUnSubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_n1n2msg_stat",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).N1N2MessageTransferStatusProcedure",
        .retprobe = false,
        .link = NULL
    },
};

int n1n2msg_funcs_cnt = sizeof(n1n2msg_funcs) / sizeof(n1n2msg_funcs[0]);

/* ------ Other API (OAM, Mt, Location) ------ */
struct attach_target other_funcs[] = {
    {
        .prog_name = "amf_loc_info",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).ProvideLocationInfoProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_domain_sel_info",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).ProvideDomainSelectionInfoProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "amf_oam_ue_context",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).OAMRegisteredUEContextProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int other_funcs_cnt = sizeof(other_funcs) / sizeof(other_funcs[0]);

#endif /* AMF API attach_target arrays not in FSM */
