#ifndef NEF_COMM_H
#define NEF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "nef_tracer.skel.h"

int attach_programs(struct nef_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // NEF_COMM_H