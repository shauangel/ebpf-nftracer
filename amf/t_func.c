#include "t_func.h"
#include <stdbool.h>

struct test_struct sub_funcs[] = {
    {
        .prog_name = "amf_stat_ch_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeSubscribeProcedure",
        .retprobe = false,
    },
    {
        .prog_name = "amf_stat_ch_unsub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeUnSubscribeProcedure",
        .retprobe = false,
    },
    {
        .prog_name = "amf_stat_ch_mod_sub",
        .func_name = "github.com/free5gc/amf/internal/sbi/processor.(*Processor).AMFStatusChangeSubscribeModifyProcedure",
        .retprobe = false,
    },
};

int sub_funcs_cnt = sizeof(sub_funcs) / sizeof(sub_funcs[0]);