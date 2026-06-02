// namespace_tracer.bpf.c
// eBPF program for namespace-aware container tracing
// Extracts all namespace identifiers for complete container context
//
// Fixed from original:
//   1. Replaced all <linux/...> headers with vmlinux.h (CO-RE) — fixes the
//      fatal mnt_namespace opaque-type compilation error.
//   2. All struct field reads now use BPF_CORE_READ() — portable across kernel
//      versions without recompilation.
//   3. numbers[level] access now has an explicit bounds check before the read
//      so the BPF verifier accepts the variable-offset array access.
//   4. net_ns inum reads directly via BPF_CORE_READ instead of the fragile
//      ns_common cast in the original.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum PID namespace nesting depth. Docker containers are always 1 level
// deep (host=0, container=1). 32 is a safe upper bound for the verifier.
#define MAX_PID_NS_LEVEL 32

// ── Structures ────────────────────────────────────────────────────────────────

struct namespace_info {
    __u64 cgroup_id;
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
    __u32 uts_ns;
    __u32 ipc_ns;
    __u32 user_ns;
    __u32 time_ns;
};

struct container_context {
    __u32 pid;
    __u32 tid;
    __u32 container_pid;
    struct namespace_info ns;
    char comm[16];
    char uts_nodename[65];
    __u64 timestamp;
};

// ── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ns_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u64);
    __type(value, struct namespace_info);
} ns_cache SEC(".maps");

// Populated by userspace with the cgroup IDs of the free5gc NF containers.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);
    __type(value, __u8);
} container_cgroups SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline int get_namespace_info(struct task_struct *task,
                                               struct namespace_info *ns_info) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return -1;

    // PID namespace
    // Note: pid_ns_for_children is the namespace new children will be placed
    // in. For free5gc NF containers this equals the container's own PID
    // namespace because the NF binary never calls unshare(CLONE_NEWPID).
    struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (pid_ns)
        ns_info->pid_ns = BPF_CORE_READ(pid_ns, ns.inum);

    // Mount namespace — previously fatal: mnt_namespace was an opaque type
    // with raw kernel headers. vmlinux.h exposes the full struct via BTF.
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (mnt_ns)
        ns_info->mnt_ns = BPF_CORE_READ(mnt_ns, ns.inum);

    // UTS namespace (hostname isolation)
    struct uts_namespace *uts_ns = BPF_CORE_READ(nsproxy, uts_ns);
    if (uts_ns)
        ns_info->uts_ns = BPF_CORE_READ(uts_ns, ns.inum);

    // IPC namespace
    struct ipc_namespace *ipc_ns = BPF_CORE_READ(nsproxy, ipc_ns);
    if (ipc_ns)
        ns_info->ipc_ns = BPF_CORE_READ(ipc_ns, ns.inum);

    // Network namespace — original used a fragile (struct ns_common *) cast
    // because of uncertainty about the offset of ns inside struct net.
    // BPF_CORE_READ resolves the correct offset from BTF at load time.
    struct net *net_ns = BPF_CORE_READ(nsproxy, net_ns);
    if (net_ns)
        ns_info->net_ns = BPF_CORE_READ(net_ns, ns.inum);

    // User namespace (UID/GID mapping)
    struct cred *cred = BPF_CORE_READ(task, real_cred);
    if (cred) {
        struct user_namespace *user_ns = BPF_CORE_READ(cred, user_ns);
        if (user_ns)
            ns_info->user_ns = BPF_CORE_READ(user_ns, ns.inum);
    }

    // Time namespace (Linux 5.6+)
    // BPF_CORE_READ handles the case where time_ns doesn't exist in older
    // kernels gracefully — it zeroes the field rather than failing.
    struct time_namespace *time_ns = BPF_CORE_READ(nsproxy, time_ns);
    if (time_ns)
        ns_info->time_ns = BPF_CORE_READ(time_ns, ns.inum);

    ns_info->cgroup_id = bpf_get_current_cgroup_id();

    return 0;
}

static __always_inline __u32 get_container_pid(struct task_struct *task) {
    struct pid *pid_struct = BPF_CORE_READ(task, thread_pid);
    if (!pid_struct)
        return 0;

    __u32 level = BPF_CORE_READ(pid_struct, level);

    // Bounds check is required before the variable-offset array access below.
    // Without it the BPF verifier rejects the program with
    // "invalid variable-length stack access".
    // level == 0 means the process is in the host (init) PID namespace —
    // not a container, skip it.
    if (level == 0 || level >= MAX_PID_NS_LEVEL)
        return 0;

    // Read the upid entry at numbers[level].
    // bpf_probe_read_kernel with the computed pointer is the verifier-safe
    // way to do variable-offset reads into a flexible array member once the
    // index is proven bounded above.
    struct upid upid = {};
    if (bpf_probe_read_kernel(&upid, sizeof(upid),
                              &pid_struct->numbers[level]) != 0)
        return 0;

    return upid.nr;
}

// ── Tracepoint ────────────────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Only trace processes belonging to known free5gc NF containers.
    __u8 *is_container = bpf_map_lookup_elem(&container_cgroups, &cgroup_id);
    if (!is_container)
        return 0;

    struct container_context *event =
        bpf_ringbuf_reserve(&ns_events, sizeof(*event), 0);
    if (!event)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u64 pid_tgid   = bpf_get_current_pid_tgid();
    event->pid       = pid_tgid >> 32;
    event->tid       = (__u32)pid_tgid;
    event->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    get_namespace_info(task, &event->ns);
    event->container_pid = get_container_pid(task);

    // UTS nodename (container hostname)
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (nsproxy) {
        struct uts_namespace *uts_ns = BPF_CORE_READ(nsproxy, uts_ns);
        if (uts_ns)
            bpf_probe_read_kernel_str(&event->uts_nodename,
                                      sizeof(event->uts_nodename),
                                      BPF_CORE_READ(uts_ns, name.nodename));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
