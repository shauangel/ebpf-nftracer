// nrf_loader.c
//
// Startup sequence:
//   1. find_nf_exe()        → PID + binary path  (cmdline-based, container-aware)
//   2. get_nf_cgroup_id()   → cgroupv2 ID        (stat of cgroup dir inode)
//   3. open_and_load()      → BPF skeleton
//   4. nrf_cgroup_map[0]    → store cgroup_id    (tracepoint filter)
//   5. attach_programs()    × 3 uprobe groups    (NF mgmt / auth / discovery)
//   6. attach_tracepoints() → connect/accept/write/read syscall hooks
//   7. ring_buffer__poll()  → event loop

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "nrf_tracer.skel.h"
#include "events.h"
#include "../common.h"
#include "nrf_functions.h"
#include "nrf_comm.h"

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
    struct nrf_tracer_bpf *skel = NULL;
    struct ring_buffer    *rb   = NULL;

    /* 1. Discover NRF container process & executable */
    char  exe_path[256] = {}
    pid_t pid;

    printf("[*] Looking for NRF container process...\n");
    pid = find_nf("nrf");
    if (pid < 0) {
        fprintf(stderr, "error: NRF not found — is the container running?\n");
        return 1;
    }
    printf("    pid=%-6d\n", pid);
    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", pid);
    ssize_t n = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
    if (n < 0) {
        perror("readlink /proc/<pid>/exe");
        return 1;
    }
    exe_path[n] = '\0';
    printf("    exe=%s\n", exe_path);

    /* 2. Get container cgroup ID */
    uint64_t cgroup_id = get_nf_cgroup_id((pid_t)pid);
    if (cgroup_id == 0) {
        fprintf(stderr, "error: failed to get cgroup ID for pid %d\n", pid);
        return 1;
    }
    printf("    cgroup_id=%llu\n\n", (unsigned long long)cgroup_id);

    /* 3. Load BPF skeleton */
    skel = nrf_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        return 1;
    }

    /* 4. Populate cgroup filter map */
    {
        uint32_t key = 0;
        err = bpf_map__update_elem(skel->maps.nrf_cgroup_map,
                                   &key, sizeof(key),
                                   &cgroup_id, sizeof(cgroup_id),
                                   BPF_ANY);
        if (err) {
            fprintf(stderr, "error: nrf_cgroup_map update: %d\n", err);
            goto cleanup;
        }
    }

    /* 5. Attach NRF API uprobes */
    printf("[*] Attaching uprobes...\n");
    if (attach_programs(skel, exe_path, pid,
                        nf_mngmt_funcs, nf_mngmt_funcs_cnt) < 0 ||
        attach_programs(skel, exe_path, pid,
                        auth_funcs, auth_funcs_cnt)           < 0 ||
        attach_programs(skel, exe_path, pid,
                        nf_disc_funcs, nf_disc_funcs_cnt)     < 0) {
        err = 1;
        goto cleanup;
    }

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

    printf("\n[*] Tracing NRF (pid=%d). Ctrl+C to stop.\n\n", pid);
    printf("%-22s  %-4s  %-9s  %s\n",
           "TIMESTAMP", "NF", "EVENT", "DETAIL");
    printf("%-22s  %-4s  %-9s  %s\n",
           "──────────────────────", "────", "─────────",
           "────────────────────────────────");

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
    detach_programs(nf_mngmt_funcs, nf_mngmt_funcs_cnt);
    detach_programs(auth_funcs,     auth_funcs_cnt);
    detach_programs(nf_disc_funcs,  nf_disc_funcs_cnt);
    nrf_tracer_bpf__destroy(skel);
    return err;
}
