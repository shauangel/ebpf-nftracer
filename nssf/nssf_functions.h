#ifndef NSSF_FUNCTIONS_H
#define NSSF_FUNCTIONS_H

#include "../common.h"

extern struct attach_target nssai_store_funcs[];
extern struct attach_target nssai_sub_funcs[];
extern struct attach_target nssai_sel_funcs[];

extern int nssai_store_funcs_cnt;
extern int nssai_sub_funcs_cnt;
extern int nssai_sel_funcs_cnt;

#endif // NSSF_FUNCTIONS_H