#include "pcf_functions.h"


/* ------ AM Policy Functions ------ */
struct attach_target am_policy_funcs[] = {
    {
        .prog_name = "pcf_am_post",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).PostPoliciesProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_am_update",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).UpdatePostPoliciesPolAssoIdProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_am_get",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleGetPoliciesPolAssoId",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_am_delete",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleDeletePoliciesPolAssoId",
        .retprobe = false,
        .link = NULL,
    },
};

int am_policy_funcs_cnt = sizeof(am_policy_funcs) / sizeof(am_policy_funcs[0]);

/* ------ BDT Policy Functions ------ */
struct attach_target bdt_policy_funcs[] = {
    {
        .prog_name = "pcf_bdt_get",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleGetBDTPolicyContextRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_bdt_update",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleUpdateBDTPolicyContextProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_bdt_create",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleCreateBDTPolicyContextRequest",
        .retprobe = false,
        .link = NULL,
    },
};

int bdt_policy_funcs_cnt = sizeof(bdt_policy_funcs) / sizeof(bdt_policy_funcs[0]);

/* ------ OAM Functions ------ */
struct attach_target oam_funcs[] = {
    {
        .prog_name = "pcf_oam_get_am",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleOAMGetAmPolicyRequest",
        .retprobe = false,
        .link = NULL,
    },
};

int oam_funcs_cnt = sizeof(oam_funcs) / sizeof(oam_funcs[0]);

/* ------ Policy Authorization Functions ------ */
struct attach_target policy_auth_funcs[] = {
    {
        .prog_name = "pcf_post_app_sess_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).postAppSessCtxProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_get_app_sess_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleGetAppSessionContext",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_delete_app_sess_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleDeleteAppSessionContext",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_mod_app_sess_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleModAppSessionContext",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_del_evnts_sub_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleDeleteEventsSubscContext",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_upd_evnts_sub_ctx",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleUpdateEventsSubscContext",
        .retprobe = false,
        .link = NULL,
    },
};

int policy_auth_funcs_cnt = sizeof(policy_auth_funcs) / sizeof(policy_auth_funcs[0]);

/* ------ SM Policy Functions ------ */
struct attach_target sm_policy_funcs[] = {
    {
        .prog_name = "pcf_create_sm_policy",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleCreateSmPolicyRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_get_sm_policy",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleGetSmPolicyContextRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_update_sm_policy",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleUpdateSmPolicyContextRequest",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "pcf_delete_sm_policy",
        .func_name = "github.com/free5gc/pcf/internal/sbi/processor.(*Processor).HandleDeleteSmPolicyContextRequest",
        .retprobe = false,
        .link = NULL,
    },
};

int sm_policy_funcs_cnt = sizeof(sm_policy_funcs) / sizeof(sm_policy_funcs[0]);


