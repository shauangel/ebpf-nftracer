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
// SEC("uprobe/nrf_registry_entry")
// int nrf_registry_entry(struct pt_regs *ctx){
//     struct event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if(!e){ return 0; }

//     __builtin_memset(e, 0, sizeof(*e));
//     fill_process_context(e);
//     fill_app_context(e, "NRF", "HandleNFRegister");
//     __builtin_memcpy(e->api, "NFRegister", sizeof("NFRegister"));
//     __builtin_memcpy(e->method, "POST", sizeof("POST"));
//     e->direction = IN;
//     e->ret = -1;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }


// SEC("uprobe/nrf_api_exit")
// int nrf_api_exit(struct pt_regs *ctx){
//     struct event *e;
//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if(!e){ return 0; }

//     __builtin_memset(e, 0, sizeof(*e));
//     fill_process_context(e);
//     fill_app_context(e, "NRF", "GinWriteResponse");
//     __builtin_memcpy(e->api, "WriteResponse", sizeof("WriteResponse"));
//     // __builtin_memcpy(e->method, "", sizeof(""));
//     e->direction = OUT;
//     e->ret = 0;

//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

/* Intercept Register API*/
SEC("uprobe/nrf_reg_args")
int nrf_reg_args(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    e->dbg = bpf_ringbuf_reserve(&debug_args, sizeof(e->dbg), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts  = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->cid = bpf_get_current_cgroup_id();

    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NFRegister", 15);
    __builtin_memcpy(e->func, "NFRegisterProcedure", 20);

    e->dbg.arg4 = PT_REGS_PARM4(ctx);
    __u64 hdr[8] = {};
    if (e->dbg.arg4) {
        bpf_probe_read_user(hdr, sizeof(hdr), (void *)e->dbg.arg4);

        e->dbg.p1 = hdr[0];
        e->dbg.l1 = hdr[1];
        e->dbg.p3 = hdr[4];
        e->dbg.l3 = hdr[5];
        e->dbg.p4 = hdr[6];
        e->dbg.l4 = hdr[7];

        if (e->dbg.p1 && e->dbg.l1 > 0 && e->dbg.l1 < sizeof(e->dbg.s1))
            bpf_probe_read_user(e->dbg.s1, e->dbg.l1, (void *)e->dbg.p1);

        if (e->dbg.p3 && e->dbg.l3 > 0 && e->dbg.l3 < sizeof(e->dbg.s3))
            bpf_probe_read_user(e->dbg.s3, e->dbg.l3, (void *)e->dbg.p3);

        if (e->dbg.p4 && e->dbg.l4 > 0 && e->dbg.l4 < sizeof(e->dbg.s4))
            bpf_probe_read_user(e->dbg.s4, e->dbg.l4, (void *)e->dbg.p4);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// /* Intercept Access Token Verif */
// SEC("uprobe/nrf_access")
// int nrf_ac_args(struct nrf_tracer.bpf
// {
//     /* data */
// };
// )