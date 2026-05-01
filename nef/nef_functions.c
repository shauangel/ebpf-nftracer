#include "nef_functions.h"


/* ------ PFD Functions ------ */
struct attach_target pfd_funcs[] = {
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetPFDManagementTransactions",
        .func_name = "nef_get_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PostPFDManagementTransactions",
        .func_name = "nef_post_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).DeletePFDManagementTransactions",
        .func_name = "nef_del_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetIndividualPFDManagementTransaction",
        .func_name = "nef_get_ind_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PutIndividualPFDManagementTransaction",
        .func_name = "nef_put_ind_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).DeleteIndividualPFDManagementTransaction",
        .func_name = "nef_del_ind_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetIndividualApplicationPFDManagement",
        .func_name = "nef_get_ind_app_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).DeleteIndividualApplicationPFDManagement",
        .func_name = "nef_del_ind_app_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PutIndividualApplicationPFDManagement",
        .func_name = "nef_put_ind_app_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PatchIndividualApplicationPFDManagement",
        .func_name = "nef_patch_ind_app_pfd_mngmt",
        .retprobe = false,
        .link = NULL,
    },
};

int pfd_funcs_cnt = sizeof(pfd_funcs) / sizeof(pfd_funcs[0]);

/* ------ PFDF Functions ------ */
struct attach_target pfdf_funcs[] = {
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetApplicationsPFD",
        .func_name = "nef_get_app_pfdf",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetIndividualApplicationPFD",
        .func_name = "nef_get_ind_app_pfdf",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PostPFDSubscriptions",
        .func_name = "nef_post_pfd_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).DeleteIndividualPFDSubscription",
        .func_name = "nef_del_ind_pfd_sub",
        .retprobe = false,
        .link = NULL,
    },
};

int pfdf_funcs_cnt = sizeof(pfdf_funcs) / sizeof(pfdf_funcs[0]);

/* ------ TI (Traffic Inference) Functions ------ */
struct attach_target ti_funcs[] = {
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetTrafficInfluenceSubscription",
        .func_name = "nef_get_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PostTrafficInfluenceSubscription",
        .func_name = "nef_post_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetIndividualTrafficInfluenceSubscription",
        .func_name = "nef_get_ind_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PutIndividualTrafficInfluenceSubscription",
        .func_name = "nef_put_ind_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).PatchIndividualTrafficInfluenceSubscription",
        .func_name = "nef_patch_ind_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).DeleteIndividualTrafficInfluenceSubscription",
        .func_name = "nef_del_ind_ti_sub",
        .retprobe = false,
        .link = NULL,
    },
};

int ti_funcs_cnt = sizeof(ti_funcs) / sizeof(ti_funcs[0]);

/* ------ Other Functions ------ */
struct attach_target other_funcs[] = {
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).SmfNotification",
        .func_name = "nef_smf_notif",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "github.com/free5gc/nef/internal/sbi/processor.(*Processor).GetOamIndex",
        .func_name = "nef_get_oam_index",
        .retprobe = false,
        .link = NULL,
    },
};

int other_funcs_cnt = sizeof(other_funcs) / sizeof(other_funcs[0]);
