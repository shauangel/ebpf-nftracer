#ifndef UDM_FUNCTIONS_H
#define UDM_FUNCTIONS_H

#include "../common.h"

extern struct attach_target evnt_exp_funcs[];
extern struct attach_target gen_auth_funcs[];
extern struct attach_target param_prov_funcs[];
extern struct attach_target subscriber_funcs[];
extern struct attach_target ue_ctx_mngmt_funcs[];

extern int evnt_exp_funcs_cnt;
extern int gen_auth_funcs_cnt;
extern int param_prov_funcs_cnt;
extern int subscriber_funcs_cnt;
extern int ue_ctx_mngmt_funcs_cnt;

#endif // UDM_FUNCTIONS_H