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
    // bpf_probe_read_kernel_str(e->func, sizeof(e->func), func_name);
    bpf_probe_read_kernel_str(e->nf, sizeof(e->nf), nf_name);
}

// Parse Args
// static __always_inline void parse_args(struct event *e, const )


/* API Interception */
/* -------------- TO-DO (Need to find the real function names) -------------- */

/* Register API*/
SEC("uprobe/nrf_reg_args")
int nrf_reg_args(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));

    fill_process_context(e);

    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "NFRegister", 15);

    e->dbg.arg4 = PT_REGS_PARM4(ctx);
    if (e->dbg.arg4) {
        bpf_probe_read_user(e->dbg.q, sizeof(e->dbg.q), (void *)e->dbg.arg4);

        // NFInstanceID
        if (e->dbg.q[0] && e->dbg.q[1] > 0 && e->dbg.q[1] < sizeof(e->dbg.buf0))
            bpf_probe_read_user(e->dbg.buf0, e->dbg.q[1], (void *)e->dbg.q[0]);
        
        // Requested NF
        if(e->dbg.q[4] && e->dbg.q[5] > 0 && e->dbg.q[5] < sizeof(e->dbg.buf2))
            bpf_probe_read_user(e->dbg.buf2, e->dbg.q[5], (void *)e->dbg.q[4]);

        // Status
        if(e->dbg.q[6] && e->dbg.q[7] > 0 && e->dbg.q[7] < sizeof(e->dbg.buf3))
            bpf_probe_read_user(e->dbg.buf3, e->dbg.q[7], (void *)e->dbg.q[6]);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Access Token Request */
SEC("uprobe/nrf_ac_args")
int nrf_ac_args(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "AccessToken", 15);

    e->dbg.arg4 = PT_REGS_PARM4(ctx);
    if (e->dbg.arg4)
        bpf_probe_read_user(e->dbg.q, sizeof(e->dbg.q), (void *)e->dbg.arg4);
        // GrantType
        if(e->dbg.q[4] && e->dbg.q[5] > 0 && e->dbg.q[5] < sizeof(e->dbg.buf0))
            bpf_probe_read_user(e->dbg.buf0, e->dbg.q[5], (void *)e->dbg.q[4]);

        // NFInstanceID
        if(e->dbg.q[6] && e->dbg.q[7] > 0 && e->dbg.q[7] < sizeof(e->dbg.buf1))
            bpf_probe_read_user(e->dbg.buf1, e->dbg.q[7], (void *)e->dbg.q[6]);

        // request NF
        if(e->dbg.q[8] && e->dbg.q[9] > 0 && e->dbg.q[9] < sizeof(e->dbg.buf2))
            bpf_probe_read_user(e->dbg.buf2, e->dbg.q[9], (void *)e->dbg.q[8]);

        // response NF
        if(e->dbg.q[10] && e->dbg.q[11] > 0 && e->dbg.q[11] < sizeof(e->dbg.buf3))
            bpf_probe_read_user(e->dbg.buf3, e->dbg.q[11], (void *)e->dbg.q[10]);

        // ???
        if(e->dbg.q[12] && e->dbg.q[13] > 0 && e->dbg.q[13] < sizeof(e->dbg.buf4))
            bpf_probe_read_user(e->dbg.buf4, e->dbg.q[13], (void *)e->dbg.q[12]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/nrf_oauth_verif")
int nrf_oauth_verif(struct pt_regs *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e){ return 0; }

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_context(e);
    __builtin_memcpy(e->nf, "NRF", 4);
    __builtin_memcpy(e->api, "OAuthVerif", 32);

    e->dbg.arg1 = PT_REGS_PARM1(ctx);
    e->dbg.arg2 = PT_REGS_PARM2(ctx);
    e->dbg.arg3 = PT_REGS_PARM3(ctx);
    e->dbg.arg4 = PT_REGS_PARM4(ctx);
    if (e->dbg.arg4)
        bpf_probe_read_user(e->dbg.q, sizeof(e->dbg.q), (void *)e->dbg.arg4);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
