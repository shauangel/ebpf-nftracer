#ifndef NSSF_COMM_H
#define NSSF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "nssf_tracer.skel.h"

int attach_programs(struct nssf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // NSSF_COMM_H