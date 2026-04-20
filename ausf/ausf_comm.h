#ifndef AUSF_COMM_H
#define AUSF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "ausf_tracer.skel.h"

int attach_programs(struct ausf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // AUSF_COMM_H