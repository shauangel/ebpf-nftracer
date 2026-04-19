#ifndef UDM_COMM_H
#define UDM_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "udm_tracer.skel.h"

int attach_programs(struct udm_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // UDM_COMM_H