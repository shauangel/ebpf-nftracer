#include "nssf_functions.h"


/* ------ Nssai Availability Store ------ */
struct attach_target nssai_store_funcs[] = {
    {
        .prog_name = "nssf_nssai_nfinst_del",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NssaiAvailabilityNfInstanceDelete",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nssf_nssai_nfinst_patch",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NssaiAvailabilityNfInstancePatch",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nssf_nssai_nfinst_update",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NssaiAvailabilityNfInstanceUpdate",
        .retprobe = false,
        .link = NULL,
    },
};

int nssai_store_funcs_cnt = sizeof(nssai_store_funcs) / sizeof(nssai_store_funcs[0]);

/* ------ Nssai Availability Subscription ------ */
struct attach_target nssai_sub_funcs[] = {
    {
        .prog_name = "nssf_nssai_sub_create",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NssaiAvailabilitySubscriptionCreate",
        .retprobe = false,
        .link = NULL,
    },
    {
        .prog_name = "nssf_nssai_sub_unsub",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NssaiAvailabilitySubscriptionUnsubscribe",
        .retprobe = false,
        .link = NULL,
    },
};

int nssai_sub_funcs_cnt = sizeof(nssai_sub_funcs) / sizeof(nssai_sub_funcs[0]);


/* ------ NssSelection Network Slice Information ------ */
struct attach_target nssai_sel_funcs[] = {
    {
        .prog_name = "nssf_nssai_sel_get",
        .func_name = "github.com/free5gc/nssf/internal/sbi/processor.(*Processor).NSSelectionSliceInformationGet",
        .retprobe = false,
        .link = NULL,
    },
};

int nssai_sel_funcs_cnt = sizeof(nssai_sel_funcs) / sizeof(nssai_sel_funcs[0]);