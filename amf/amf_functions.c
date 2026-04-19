#include "amf_functions.h"


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