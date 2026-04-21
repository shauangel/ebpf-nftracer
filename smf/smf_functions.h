#ifndef SMF_FUNCTIONS_H
#define SMF_FUNCTIONS_H

#include "../common.h"

extern struct attach_target association_funcs[];
extern struct attach_target charging_trigger_funcs[];
extern struct attach_target datapath_funcs[];
extern struct attach_target oam_funcs[];
extern struct attach_target pdu_session_funcs[];
extern struct attach_target ulcl_funcs[];

extern int association_funcs_cnt;
extern int charging_trigger_funcs_cnt;
extern int datapath_funcs_cnt;
extern int oam_funcs_cnt;
extern int pdu_session_funcs_cnt;
extern int ulcl_funcs_cnt;

#endif // SMF_FUNCTIONS_H