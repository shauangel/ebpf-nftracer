#include "smf_functions.h"


/* ------ Association API ------ */
struct attach_target association_funcs[] = {
    {
        .prog_name = "smf_asso_with_upf",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).ToBeAssociatedWithUPF",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_release_all_upf",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).ReleaseAllResourcesOfUPFgithub.com/free5gc/smf/internal/sbi/processor.(*Processor).ReleaseAllResourcesOfUPF",
        .retprobe = false,
        .link = NULL,
    },
};

int association_funcs_cnt = sizeof(association_funcs) / sizeof(association_funcs[0]);

/* ------ Charging Trigger API ------ */
struct attach_target charging_trigger_funcs[] = {
    {
        .prog_name = "smf_create_chg_session",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).CreateChargingSession",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_update_chg_session",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).UpdateChargingSession",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_release_chg_session",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).ReleaseChargingSession",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_chg_usage_quota",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).ReportUsageAndUpdateQuota",
        .retprobe = false,
        .link = NULL,
    },
};

int charging_trigger_funcs_cnt = sizeof(charging_trigger_funcs) / sizeof(charging_trigger_funcs[0]);

/* ------ Datapath Functions ------ */
struct attach_target datapath_funcs[] = {
    {
        .prog_name = "smf_act_upf_session",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.ActivateUPFSession",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_query_report",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.QueryReport",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_est_handler",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).EstHandler",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_release_tunnel",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.ReleaseTunnel",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_release_dc_tunnel",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.ReleaseDcTunnel",
        .retprobe = false,
        .link = NULL,
    },
};

int datapath_funcs_cnt = sizeof(datapath_funcs) / sizeof(datapath_funcs[0]);

/* ------ OAM API ------ */
struct attach_target oam_funcs[] = {
    {
        .prog_name = "smf_oam_get_ue_pdu",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandleOAMGetUEPDUSessionInfo",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_oam_get_smf_info",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandleGetSMFUserPlaneInfo",
        .retprobe = false,
        .link = NULL,
    },
};

int oam_funcs_cnt = sizeof(oam_funcs) / sizeof(oam_funcs[0]);

/* ------ PDU_Session API ------ */
struct attach_target pdu_session_funcs[] = {
    {
        .prog_name = "smf_pdu_sm_create",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandlePDUSessionSMContextCreate",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_pdu_sm_update",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandlePDUSessionSMContextUpdate",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_pdu_sm_release",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).HandlePDUSessionSMContextRelease",
        .retprobe = false,
        .link = NULL,
    },
};

int pdu_session_funcs_cnt = sizeof(pdu_session_funcs) / sizeof(pdu_session_funcs[0]);

/* ------ ULCL Procedure ------ */
struct attach_target ulcl_funcs[] = {
    {
        .prog_name = "smf_establish_psa2",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.(*Processor).EstablishPSA2",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_establish_ulcl",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.EstablishULCL",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_update_psa2_dl",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.UpdatePSA2DownLink",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_establish_ran_tunnel",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.EstablishRANTunnelInfo",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "smf_update_ran_iupf_ul",
        .func_name = "github.com/free5gc/smf/internal/sbi/processor.UpdateRANAndIUPFUpLink",
        .retprobe = false,
        .link = NULL,
    },
};

int ulcl_funcs_cnt = sizeof(ulcl_funcs) / sizeof(ulcl_funcs[0]);
