#ifndef UDR_COMM_H
#define UDR_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "udr_tracer.skel.h"

int attach_programs(struct udr_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // UDR_COMM_H