#ifndef AMF_FUNCTIONS_H
#define AMF_FUNCTIONS_H

#include "../common.h"

extern struct attach_target sub_funcs[];
extern struct attach_target ue_ctx_funcs[];
extern struct attach_target callback_funcs[];
extern struct attach_target evnt_funcs[];
extern struct attach_target n1n2msg_funcs[];
extern struct attach_target other_funcs[];
extern int sub_funcs_cnt;
extern int ue_ctx_funcs_cnt;
extern int callback_funcs_cnt;
extern int evnt_funcs_cnt;
extern int n1n2msg_funcs_cnt;
extern int other_funcs_cnt;

#endif // AMF_FUNCTIONS_H