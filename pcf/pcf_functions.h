#ifndef PCF_FUNCTIONS_H
#define PCF_FUNCTIONS_H

#include "../common.h"

extern struct attach_target am_policy_funcs[];
extern struct attach_target bdt_policy_funcs[];
extern struct attach_target oam_funcs[];
extern struct attach_target policy_auth_funcs[];
extern struct attach_target sm_policy_funcs[];

extern int am_policy_funcs_cnt;
extern int bdt_policy_funcs_cnt;
extern int oam_funcs_cnt;
extern int policy_auth_funcs_cnt;
extern int sm_policy_funcs_cnt;

#endif // PCF_FUNCTIONS_H