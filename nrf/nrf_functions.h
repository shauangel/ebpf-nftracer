#ifndef NRF_FUNCTIONS_H
#define NRF_FUNCTIONS_H

#include "common.h"

extern struct attach_target auth_funcs[];
extern struct attach_target nf_disc_funcs[];
extern struct attach_target nf_mngmt_funcs[];

extern int auth_funcs_cnt;
extern int nf_disc_funcs_cnt;
extern int nf_mngmt_funcs_cnt;

#endif // NRF_FUNCTIONS_H