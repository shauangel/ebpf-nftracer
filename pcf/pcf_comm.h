#ifndef PCF_COMM_H
#define PCF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "pcf_tracer.skel.h"

int attach_programs(struct pcf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // PCF_COMM_H