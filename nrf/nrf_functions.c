#include "nrf_functions.h"


/* ------ Access Token API ------ */
struct attach_target auth_funcs[] = {
    {
        .prog_name = "nrf_access_token",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).AccessTokenProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int auth_funcs_cnt = sizeof(auth_funcs) / sizeof(auth_funcs[0]);

/* ------ NF Discovery API ------ */
struct attach_target nf_disc_funcs[] = {
    {
        .prog_name = "nrf_nf_discovery",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).NFDiscoveryProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int nf_disc_funcs_cnt = sizeof(nf_disc_funcs) / sizeof(nf_disc_funcs[0]);


/* ------ NF Management API ------ */
struct attach_target nf_mngmt_funcs[] = {
    {
        .prog_name = "nrf_nf_register",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).NFRegisterProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_nf_deregister",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).NFDeregisterProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_get_nf_inst",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).GetNFInstanceProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_get_nf_inst_list",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).GetNFInstancesProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_update_nf_inst",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).UpdateNFInstanceProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_create_sub",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).CreateSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_remove_sub",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).RemoveSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nrf_update_sub",
        .func_name = "github.com/free5gc/nrf/internal/sbi/processor.(*Processor).UpdateSubscriptionProcedure",
        .retprobe = false,
        .link = NULL,
    },
};

int nf_mngmt_funcs_cnt = sizeof(nf_mngmt_funcs) / sizeof(nf_mngmt_funcs[0]);