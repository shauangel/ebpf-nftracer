#ifndef NEF_FUNCTIONS_H
#define NEF_FUNCTIONS_H

#include "../common.h"

extern struct attach_target pfd_funcs[];
extern struct attach_target pfdf_funcs[];
extern struct attach_target ti_funcs[];
extern struct attach_target other_funcs[];

extern int pfd_funcs_cnt;
extern int pfdf_funcs_cnt;
extern int ti_funcs_cnt;
extern int other_funcs_cnt;

#endif // NEF_FUNCTIONS_H