#ifndef AMF_TEST_UTIL_H
#define AMF_TEST_UTIL_H

/*
 * test_util.h — small helpers shared by test_map_create.c and
 * test_map_walk.c. Both files talk to a REAL kernel: every map here is
 * created via bpf_map_create(), the same libbpf entry point the kernel's
 * bpf() syscall is reached through, with the exact type/key/value/
 * max_entries layout sm_map.c declares for sm_nodes/sm_edges (see
 * sm_map.h). No mocking, no clang -target bpf compile of sm_map.c itself
 * -- BPF_MAP_TYPE_HASH maps are created and manipulated entirely from
 * userspace, no BPF program required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "../sm_map.h"

/* Creating/updating a real kernel BPF map requires CAP_BPF (plus
 * CAP_SYS_ADMIN on kernels older than 5.8) -- in practice, root. Fail
 * fast with a clear message instead of letting every test in the binary
 * report a confusing EPERM one CHECK() at a time. */
static inline void require_root(const char *argv0)
{
    if (geteuid() != 0) {
        fprintf(stderr,
                "%s: must run as root -- these tests create real "
                "BPF_MAP_TYPE_HASH maps via the bpf() syscall.\n"
                "Try: sudo ./%s\n", argv0, argv0);
        exit(1);
    }
}

static inline int create_sm_nodes_map(const char *name)
{
    return bpf_map_create(BPF_MAP_TYPE_HASH, name,
                           sizeof(struct sm_node_key), sizeof(struct sm_node_val),
                           SM_NODE_MAP_MAX_ENTRIES, NULL);
}

static inline int create_sm_edges_map(const char *name)
{
    return bpf_map_create(BPF_MAP_TYPE_HASH, name,
                           sizeof(struct sm_edge_key), sizeof(struct sm_edge_val),
                           SM_EDGE_MAP_MAX_ENTRIES, NULL);
}

#endif /* AMF_TEST_UTIL_H */
