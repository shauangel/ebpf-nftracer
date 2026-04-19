#ifndef COMMON_H
#define COMMON_H

#include <bpf/libbpf.h>
#include <stddef.h>

struct attach_target {
    const char *prog_name;   // BPF program name in skeleton
    const char *func_name;   // userspace function symbol to hook
    bool retprobe;
    struct bpf_link *link;   // link of attached probe
};


int find_nf_exe(const char *nf_name, char *exe_path, size_t exe_path_sz);

#endif