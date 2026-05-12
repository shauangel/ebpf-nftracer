#include "udr_functions.h"


/* ------  ------ */
struct attach_target auth_funcs[] = {
    {
        .prog_name = "",
        .func_name = "",
        .retprobe = false,
        .link = NULL,
    },
};

int auth_funcs_cnt = sizeof(auth_funcs) / sizeof(auth_funcs[0]);
