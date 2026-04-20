#ifndef NRF_COMM_H
#define NRF_COMM_H

#include <bpf/libbpf.h>
#include "common.h"
#include "nrf_tracer.skel.h"

int attach_programs(struct nrf_tracer_bpf *skel,
                   const char *bin_path,
                   pid_t pid,
                   struct attach_target *targets,
                   int cnt);

void detach_programs(struct attach_target *targets, int cnt);

#endif // NRF_COMM_H