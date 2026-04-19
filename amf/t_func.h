#ifndef T_FUNC_H
#define T_FUNC_H

#include <stdbool.h>

struct test_struct {
    const char *prog_name;   // BPF program name in skeleton
    const char *func_name;   // userspace function symbol to hook
    bool retprobe;
};


extern struct test_struct sub_funcs[];
extern int sub_funcs_cnt;

#endif //T_FUNC_H