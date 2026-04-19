#ifndef AMF_COMM_H
#define AMF_COMM_H

#include <bpf/libbpf.h>
#include "../common.h"
#include "amf_tracer.skel.h"

int attach_programs(struct amf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif