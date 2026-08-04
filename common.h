#ifndef COMMON_H
#define COMMON_H

#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct attach_target {
    const char      *prog_name;   // BPF program name in skeleton
    const char      *func_name;   // userspace function symbol to hook
    bool             retprobe;
    struct bpf_link *link;        // link of attached probe
};

/**
 * find_nf - locate a running NF process by exact /proc/<pid>/comm match.
 *
 * Scans /proc for a process whose comm equals nf_name exactly.
 * Returns the PID, or -1 if not found.
 */
int find_nf(const char *nf_name);

/**
 * find_nf_exe - locate a running NF process by cmdline pattern.
 *
 * Scans /proc looking for a process whose cmdline contains one of:
 *   ./bin/<nf_name>  |  /bin/<nf_name>  |  free5gc/bin/<nf_name>
 *
 * Fills exe_path (via /proc/<pid>/exe readlink) and returns the PID,
 * or -1 if not found.
 */
int find_nf_exe(const char *nf_name, char *exe_path, size_t exe_path_sz);

/**
 * get_nf_cgroup_id - return the cgroupv2 ID for a given PID.
 *
 * Reads /proc/<pid>/cgroup for the unified-hierarchy line ("0::/..."),
 * then stats /sys/fs/cgroup/<path>.  On cgroupv2 the directory inode
 * number equals the cgroup ID used by bpf_get_current_cgroup_id().
 *
 * Returns the cgroup_id on success, 0 on failure.
 */
uint64_t get_nf_cgroup_id(pid_t pid);

#endif
