#include "ausf_functions.h"


/* ------ UE Authentication Functions ------ */
struct attach_target ue_auth_funcs[] = {
    {
        .prog_name = "ausf_auth_aka_confirm",
        .func_name = "github.com/free5gc/ausf/internal/sbi/processor.(*Processor).Auth5gAkaComfirmRequestProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "ausf_ue_auth_post",
        .func_name = "github.com/free5gc/ausf/internal/sbi/processor.(*Processor).UeAuthPostRequestProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "ausf_eap_auth_confirm",
        .func_name = "github.com/free5gc/ausf/internal/sbi/processor.(*Processor).EapAuthComfirmRequestProcedure",
        .retprobe = false,
        .link = NULL,
    },

};

int ue_auth_funcs_cnt = sizeof(ue_auth_funcs) / sizeof(ue_auth_funcs[0]);