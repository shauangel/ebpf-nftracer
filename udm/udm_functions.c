#include "udm_functions.h"

/* ------ Event Exposure Functions ------ */
struct attach_target evnt_exp_funcs[] = {
    {
        .prog_name = "udm_create_ee_sub",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).CreateEeSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_delete_ee_sub",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).DeleteEeSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_update_ee_sub",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UpdateEeSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int evnt_exp_funcs_cnt = sizeof(evnt_exp_funcs) / sizeof(evnt_exp_funcs[0]);

/* ------ Generate Authentication Data Functions ------ */
struct attach_target gen_auth_funcs[] = {
    {
        .prog_name = "udm_confirm_auth_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).ConfirmAuthDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_generate_auth_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GenerateAuthDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int gen_auth_funcs_cnt = sizeof(gen_auth_funcs) / sizeof(gen_auth_funcs[0]);

/* ------ Parameter Provision Functions ------ */
struct attach_target param_prov_funcs[] = {
    {
        .prog_name = "udm_para_prov_update",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UpdateProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int param_prov_funcs_cnt = sizeof(param_prov_funcs) / sizeof(param_prov_funcs[0]);

/* ------ Subscriber Data Management Functions ------ */
struct attach_target subscriber_funcs[] = {
    {
        .prog_name = "udm_get_am_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetAmDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_id_trans_rslt",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetIdTranslationResultProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_supi",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetSupiProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_shared_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetSharedDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_sm_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetSmDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_nssai",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetNssaiProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_smf_slct_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetSmfSelectDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_sub_shared_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).SubscribeToSharedDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_subscribe",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).SubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_unsub_shared_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UnsubscribeForSharedDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_unsubscribe",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UnsubscribeProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_modify",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).ModifyProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_mod_shared_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).ModifyForSharedDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_trace_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetTraceDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_ue_ctx_smf_data",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetUeContextInSmfDataProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int subscriber_funcs_cnt = sizeof(subscriber_funcs) / sizeof(subscriber_funcs[0]);

/* ------ UE Context management Functions ------ */
struct attach_target ue_ctx_mngmt_funcs[] = {
    {
        .prog_name = "udm_get_amf3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetAmf3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_get_amfnon3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).GetAmfNon3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_reg_amf3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).RegistrationAmf3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_reg_amfnon3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).RegisterAmfNon3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_update_amf3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UpdateAmf3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_update_amfnon3gpp_access",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).UpdateAmfNon3gppAccessProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_dereg_smf_reg",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).DeregistrationSmfRegistrationsProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "udm_reg_smf_reg",
        .func_name = "github.com/free5gc/udm/internal/sbi/processor.(*Processor).RegistrationSmfRegistrationsProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int ue_ctx_mngmt_funcs_cnt = sizeof(ue_ctx_mngmt_funcs) / sizeof(ue_ctx_mngmt_funcs[0]);
