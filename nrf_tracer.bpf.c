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

    SEC("uprobe/nrf_reg_args")
    int nrf_reg_args(struct pt_regs *ctx){
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if(!e){ return 0; }

        __builtin_memset(e, 0, sizeof(*e));

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        e->ts  = bpf_ktime_get_ns();
        e->pid = pid_tgid >> 32;
        e->tid = (__u32)pid_tgid;
        e->cid = bpf_get_current_cgroup_id();

        __builtin_memcpy(e->nf, "NRF", 4);
        __builtin_memcpy(e->api, "NFRegisterProc", 15);
        __builtin_memcpy(e->func, "NFRegisterProcedure", 20);

        // e->arg1 = PT_REGS_PARM1(ctx);
        // e->arg2 = PT_REGS_PARM2(ctx);
        // e->arg3 = PT_REGS_PARM3(ctx);
        e->arg4 = PT_REGS_PARM4(ctx);
        __u64 hdr[8] = {};
        if (e->arg4) {
            bpf_probe_read_user(hdr, sizeof(hdr), (void *)e->arg4);

            e->p1 = hdr[0];
            e->l1 = hdr[1];
            e->p3 = hdr[4];
            e->l3 = hdr[5];
            e->p4 = hdr[6];
            e->l4 = hdr[7];

            if (e->p1 && e->l1 > 0 && e->l1 < sizeof(e->s1))
                bpf_probe_read_user(e->s1, e->l1, (void *)e->p1);

            if (e->p3 && e->l3 > 0 && e->l3 < sizeof(e->s3))
                bpf_probe_read_user(e->s3, e->l3, (void *)e->p3);

            if (e->p4 && e->l4 > 0 && e->l4 < sizeof(e->s4))
                bpf_probe_read_user(e->s4, e->l4, (void *)e->p4);
        }

        bpf_ringbuf_submit(e, 0);
        return 0;
    }