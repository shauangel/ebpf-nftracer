// amf_loader.c


#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "amf_tracer.skel.h"
#include "../events.h"
#include "../common.h"
#include "amf_functions.h"
#include "amf_comm.h"

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { (void)sig; stop = 1; }

/* ── Tracepoint targets ─────────────────────────────────────────────────── */

static struct tp_target syscall_tps[] = {
    { "syscalls", "sys_enter_connect", "trace_connect_enter", NULL },
    { "syscalls", "sys_exit_connect",  "trace_connect_exit",  NULL },
    { "syscalls", "sys_enter_accept4", "trace_accept_enter",  NULL },
    { "syscalls", "sys_exit_accept4",  "trace_accept_exit",   NULL },
    { "syscalls", "sys_enter_write",   "trace_write_enter",   NULL },
    { "syscalls", "sys_exit_read",     "trace_read_exit",     NULL },
};
static int syscall_tps_cnt = sizeof(syscall_tps) / sizeof(syscall_tps[0]);

/* ── Display helpers ────────────────────────────────────────────────────── */

static void fmt_ts(uint64_t ns, char *buf, size_t len)
{
    uint64_t s  = ns / 1000000000ULL;
    uint64_t us = (ns % 1000000000ULL) / 1000;
    snprintf(buf, len, "%02u:%02u:%02u.%06llu",
             (unsigned)(s / 3600) % 24,
             (unsigned)(s / 60)   % 60,
             (unsigned) s         % 60,
             (unsigned long long)us);
}

static void fmt_ipv4(uint32_t addr_net, uint16_t port, char *buf, size_t len)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr_net, ip, sizeof(ip));
    snprintf(buf, len, "%s:%u", ip, port);
}


/* ── Ring buffer event handler ──────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    const struct event *e = data;
    char ts[24], addr[48];
    fmt_ts(e->ts, ts, sizeof(ts));

    switch (e->type) {

    case EVT_API_CALL:
        printf("[%s] %-4s  API      %-24s  pid=%-6u tid=%u\n",
               ts, e->nf, e->api, e->pid, e->tid);
        break;

    case EVT_CONNECT:
        fmt_ipv4(e->dest_ip, e->dest_port, addr, sizeof(addr));
        printf("[%s] %-4s  CONNECT  → %-22s  pid=%u\n",
               ts, e->nf, addr, e->pid);
        break;

    case EVT_ACCEPT:
        fmt_ipv4(e->dest_ip, e->dest_port, addr, sizeof(addr));
        printf("[%s] %-4s  ACCEPT   ← %-22s  pid=%u  fd=%lld\n",
               ts, e->nf, addr, e->pid, (long long)e->ret);
        break;

    case EVT_WRITE:
        printf("[%s] %-4s  WRITE    %-6llu bytes  pid=%u\n",
               ts, e->nf, (unsigned long long)e->bytes, e->pid);
        break;

    case EVT_READ:
        printf("[%s] %-4s  READ     %-6llu bytes  pid=%u\n",
               ts, e->nf, (unsigned long long)e->bytes, e->pid);
        break;

    default:
        printf("[%s] %-4s  UNKNOWN  type=%u\n", ts, e->nf, e->type);
        break;
    }
    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    int err = 0;
    struct amf_tracer_bpf *skel = NULL;
    struct ring_buffer    *rb   = NULL;

    /* 1. Discover AMF container process */
    char  exe_path[256] = {};
    pid_t pid;

    printf("[*] Looking for AMF container process...\n");
    pid = find_nf("amf");
    if (pid < 0) {
        fprintf(stderr, "error: AMF not found — is the container running?\n");
        return 1;
    }
    printf("    pid=%-6d\n", pid);
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    printf("    exe=%s\n\n", exe_path);

    /* 2. Get container cgroup ID */
    uint64_t cgroup_id = get_nf_cgroup_id((pid_t)pid);
    if (cgroup_id == 0) {
        fprintf(stderr, "error: failed to get cgroup ID for pid %d\n", pid);
        return 1;
    }
    printf("    cgroup_id=%llu\n\n", (unsigned long long)cgroup_id);


    /* 3. Load BPF skeleton */
    skel = amf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        return 1;
    }

    /* 4. Populate cgroup filter map */
    {
        uint32_t key = 0;
        err = bpf_map__update_elem(skel->maps.amf_cgroup_map,
                                   &key, sizeof(key),
                                   &cgroup_id, sizeof(cgroup_id),
                                   BPF_ANY);
        if (err) {
            fprintf(stderr, "error: amf_cgroup_map update: %d\n", err);
            goto cleanup;
        }
    }

    /* 4b. Populate the threat-aware FSM (sm_nodes / sm_edges hash maps) */
    printf("[*] Loading state machine...\n");
    if (sm_map_populate(skel) < 0) {
        err = 1;
        goto cleanup;
    }

    /* 5. Attach threat-aware AMF FSM uprobes (one group per FSM node --
     * see amf_functions.c / amf/verified_attach_points.txt) */
    printf("[*] Attaching state-machine uprobes...\n");
    if (attach_programs(skel, exe_path, pid, reg_received_funcs,            reg_received_funcs_cnt)            < 0 ||
        attach_programs(skel, exe_path, pid, context_lookup_funcs,          context_lookup_funcs_cnt)          < 0 ||
        attach_programs(skel, exe_path, pid, identity_pending_funcs,        identity_pending_funcs_cnt)        < 0 ||
        attach_programs(skel, exe_path, pid, auth_vector_pending_funcs,     auth_vector_pending_funcs_cnt)     < 0 ||
        attach_programs(skel, exe_path, pid, nas_authenticating_funcs,      nas_authenticating_funcs_cnt)      < 0 ||
        attach_programs(skel, exe_path, pid, nas_security_pending_funcs,    nas_security_pending_funcs_cnt)    < 0 ||
        attach_programs(skel, exe_path, pid, udm_registering_funcs,         udm_registering_funcs_cnt)         < 0 ||
        attach_programs(skel, exe_path, pid, subscription_loading_funcs,    subscription_loading_funcs_cnt)    < 0 ||
        attach_programs(skel, exe_path, pid, policy_associating_funcs,      policy_associating_funcs_cnt)      < 0 ||
        attach_programs(skel, exe_path, pid, ue_context_ready_funcs,        ue_context_ready_funcs_cnt)        < 0 ||
        attach_programs(skel, exe_path, pid, sm_context_pending_funcs,      sm_context_pending_funcs_cnt)      < 0 ||
        attach_programs(skel, exe_path, pid, initial_context_setup_funcs,   initial_context_setup_funcs_cnt)   < 0 ||
        attach_programs(skel, exe_path, pid, registered_connected_funcs,    registered_connected_funcs_cnt)    < 0 ||
        attach_programs(skel, exe_path, pid, reg_rejected_funcs,            reg_rejected_funcs_cnt)            < 0 ||
        attach_programs(skel, exe_path, pid, auth_failed_funcs,             auth_failed_funcs_cnt)             < 0 ||
        attach_programs(skel, exe_path, pid, security_failed_funcs,         security_failed_funcs_cnt)         < 0 ||
        attach_programs(skel, exe_path, pid, security_policy_violation_funcs, security_policy_violation_funcs_cnt) < 0 ||
        attach_programs(skel, exe_path, pid, nf_timeout_funcs,              nf_timeout_funcs_cnt)              < 0 ||
        attach_programs(skel, exe_path, pid, slice_rejected_funcs,          slice_rejected_funcs_cnt)          < 0 ||
        attach_programs(skel, exe_path, pid, context_setup_failed_funcs,    context_setup_failed_funcs_cnt)    < 0 ||
        attach_programs(skel, exe_path, pid, cleanup_required_funcs,        cleanup_required_funcs_cnt)        < 0 ||
        attach_programs(skel, exe_path, pid, fsm_edge_funcs,                fsm_edge_funcs_cnt)                < 0) {
        err = 1;
        goto cleanup;
    }

    /* NOT part of the 23-state threat-aware FSM — see
     * amf/missing_attach_points.txt. Disabled to match the #if 0'd
     * arrays in amf_functions.c / programs in amf_tracer.bpf.c. */
#if 0
    printf("[*] Attaching uprobes...\n");
    if (attach_programs(skel, exe_path, pid, sub_funcs,      sub_funcs_cnt)      < 0 ||
        attach_programs(skel, exe_path, pid, ue_ctx_funcs,   ue_ctx_funcs_cnt)   < 0 ||
        attach_programs(skel, exe_path, pid, callback_funcs, callback_funcs_cnt) < 0 ||
        attach_programs(skel, exe_path, pid, evnt_funcs,     evnt_funcs_cnt)     < 0 ||
        attach_programs(skel, exe_path, pid, n1n2msg_funcs,  n1n2msg_funcs_cnt)  < 0 ||
        attach_programs(skel, exe_path, pid, other_funcs,    other_funcs_cnt)    < 0) {
        err = 1;
        goto cleanup;
    }
#endif

    /* 6. Attach syscall tracepoints */
    printf("[*] Attaching tracepoints...\n");
    if (attach_tracepoints(skel, syscall_tps, syscall_tps_cnt) < 0) {
        err = 1;
        goto cleanup;
    }

    /* 7. Ring buffer + event loop */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: ring_buffer__new failed\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\n[*] Tracing AMF (pid=%d). Ctrl+C to stop.\n\n", pid);
    printf("%-4s  %s\n", "NF", "API");
    printf("%-4s  %s\n", "────", "────────────────────────────────");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
        err = 0;
    }

cleanup:
    printf("\n[*] Detaching...\n");
    ring_buffer__free(rb);
    detach_tracepoints(syscall_tps, syscall_tps_cnt);
    detach_programs(reg_received_funcs,             reg_received_funcs_cnt);
    detach_programs(context_lookup_funcs,            context_lookup_funcs_cnt);
    detach_programs(identity_pending_funcs,          identity_pending_funcs_cnt);
    detach_programs(auth_vector_pending_funcs,       auth_vector_pending_funcs_cnt);
    detach_programs(nas_authenticating_funcs,        nas_authenticating_funcs_cnt);
    detach_programs(nas_security_pending_funcs,      nas_security_pending_funcs_cnt);
    detach_programs(udm_registering_funcs,           udm_registering_funcs_cnt);
    detach_programs(subscription_loading_funcs,      subscription_loading_funcs_cnt);
    detach_programs(policy_associating_funcs,        policy_associating_funcs_cnt);
    detach_programs(ue_context_ready_funcs,          ue_context_ready_funcs_cnt);
    detach_programs(sm_context_pending_funcs,        sm_context_pending_funcs_cnt);
    detach_programs(initial_context_setup_funcs,     initial_context_setup_funcs_cnt);
    detach_programs(registered_connected_funcs,      registered_connected_funcs_cnt);
    detach_programs(reg_rejected_funcs,              reg_rejected_funcs_cnt);
    detach_programs(auth_failed_funcs,               auth_failed_funcs_cnt);
    detach_programs(security_failed_funcs,           security_failed_funcs_cnt);
    detach_programs(security_policy_violation_funcs, security_policy_violation_funcs_cnt);
    detach_programs(nf_timeout_funcs,                nf_timeout_funcs_cnt);
    detach_programs(slice_rejected_funcs,            slice_rejected_funcs_cnt);
    detach_programs(context_setup_failed_funcs,      context_setup_failed_funcs_cnt);
    detach_programs(cleanup_required_funcs,          cleanup_required_funcs_cnt);
    detach_programs(fsm_edge_funcs,                  fsm_edge_funcs_cnt);
#if 0
    detach_programs(sub_funcs,      sub_funcs_cnt);
    detach_programs(ue_ctx_funcs,   ue_ctx_funcs_cnt);
    detach_programs(callback_funcs, callback_funcs_cnt);
    detach_programs(evnt_funcs,     evnt_funcs_cnt);
    detach_programs(n1n2msg_funcs,  n1n2msg_funcs_cnt);
    detach_programs(other_funcs,    other_funcs_cnt);
#endif
    amf_tracer_bpf__destroy(skel);
    return err;
}
