#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

// Define map structure (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");

/* General helper function */
// Process Context
static __always_inline void fill_process_context(struct event *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts  = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->cid = bpf_get_current_cgroup_id();
}

// Application Context
static __always_inline void fill_app_context(struct event *e, const char *nf_name, const char *func_name)
{
    bpf_probe_read_kernel_str(e->func, sizeof(e->func), func_name);
    bpf_probe_read_kernel_str(e->nf, sizeof(e->nf), nf_name);
}


/* API Interception */
/* -------------- TO-DO (Need to find the real function names) -------------- */
SEC("uprobe/nrf_registry_entry")
int nrf_registry_entry(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    fill_app_context(e, "NRF", "HandleNFRegister");
    __builtin_memcpy(e->api, "NFRegister", sizeof("NFRegister"));
    __builtin_memcpy(e->method, "POST", sizeof("POST"));
    e->direction = IN;
    e->ret = -1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// SEC("uretprobe/nrf_registry_exit")
// int nrf_registry_exit(struct pt_regs *ctx){
//     struct event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if(!e){ return 0; }

//     __builtin_memset(e, 0, sizeof(*e));
//     fill_process_context(e);
//     fill_app_context(e, "NRF", "HandleNFRegister");
//     __builtin_memcpy(e->api, "NFRegister", sizeof("NFRegister"));
//     __builtin_memcpy(e->method, "POST", sizeof("POST"));
//     e->direction = OUT;
//     e->ret = 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }