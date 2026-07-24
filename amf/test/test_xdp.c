/*
 * test_xdp.c — small live monitor for ../amf_xdp.c.
 *
 * Loads the real, compiled amf_xdp.o, attaches amf_xdp_enforce() as an
 * actual XDP program on a real network interface (default: veth5538fab,
 * the interface ../amf_xdp.c's own file header documents as its attach
 * target), then once a second reads and prints amf_xdp_stats
 * (PASS/DROP/STATE_INVALID) and dumps ue_state_map, until Ctrl+C, at
 * which point it detaches cleanly.
 *
 * This replaces an earlier version of this file that fed
 * amf_xdp_enforce() synthetic packets via BPF_PROG_TEST_RUN. That was
 * fine for point-checking the parser in isolation, but it can't show the
 * thing that actually matters: does amf_xdp_enforce() correctly tell real
 * SCTP/NGAP traffic apart from everything else (HTTP included) AS IT
 * ACTUALLY ARRIVES on the wire. This version answers that directly --
 * run it, then generate some ordinary HTTP traffic across the same
 * interface (amf_xdp_stats must not move) and some real SCTP/NGAP
 * traffic (it must), and watch it live.
 *
 * Usage:
 *   sudo ./test_xdp [ifname]     # default: veth5538fab
 *   ^C to detach and exit.
 *
 * Requires: Linux + CONFIG_BPF_SYSCALL, libbpf (bpf_xdp_attach()/
 * bpf_xdp_detach(), i.e. libbpf >= 0.6), root (attaching an XDP program
 * and reading BPF maps both need real BPF/net privileges), the named
 * interface to already exist, and amf_xdp.o already built (`make` in
 * this directory). See xdp_test.md for a full walkthrough.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>      /* inet_ntop()/INET_ADDRSTRLEN -- printing ue_state_map's source IPs */
#include <net/if.h>         /* if_nametoindex() -- interface name -> ifindex */
#include <linux/if_link.h>  /* XDP_FLAGS_* -- attach-mode flags for bpf_xdp_attach() */

#include <bpf/bpf.h>     /* bpf_map_lookup_elem()/bpf_map_get_next_key() -- real bpf() syscalls */
#include <bpf/libbpf.h>  /* bpf_object__open_file/load, bpf_xdp_attach/detach, find_program/map_by_name */

#include "test_util.h"  /* require_root() */
#include "fixtures.h"   /* fx_populate_nodes()/fx_populate_edges() -- the real 29/52-entry FSM table */
#include "../sm_map.h"  /* SM_NAME_MAX -- ue_state_map's state field is this size, see struct ue_val below */

#define XDP_OBJ_PATH  "amf_xdp.o"       /* built by this directory's Makefile -- see the amf_xdp.o rule */
#define XDP_PROG_NAME "amf_xdp_enforce" /* the SEC("xdp") function's C name in ../amf_xdp.c */
#define DEFAULT_IFACE "veth5538fab"     /* ../amf_xdp.c's own documented attach target; override via argv[1] */

/* ── mirrors of amf_xdp.c's PRIVATE constants/structs ──────────────────
 * Neither of these is in sm_map.h -- both are local to ../amf_xdp.c,
 * which this file only ever loads as a compiled .o, never #includes as
 * source. Keep in sync with ../amf_xdp.c by inspection (same convention
 * fixtures.h uses for ../amf_comm.c's FSM table). */

/* == amf_xdp.c's `enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };` */
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };
static const char *const stat_name[STAT_MAX] = { "PASS", "DROP", "STATE_INVALID" };

/* == amf_xdp.c's `struct ue_val { char state[SM_NAME_MAX]; __u64 last_seen_ns; };`
 * SM_NAME_MAX comes from sm_map.h (shared, real), so this struct's
 * layout is guaranteed to match ../amf_xdp.c's copy byte-for-byte. */
struct ue_val {
    char     state[SM_NAME_MAX];
    uint64_t last_seen_ns;
};

static volatile sig_atomic_t g_stop;
static void handle_signal(int sig) { (void)sig; g_stop = 1; }

/* bpf_ktime_get_ns() (what amf_xdp.c stamps ue_val.last_seen_ns with)
 * returns nanoseconds since boot, i.e. CLOCK_MONOTONIC -- this is the
 * userspace equivalent, so "now - last_seen_ns" below is a real,
 * comparable age. */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void print_ts(void)
{
    time_t t = time(NULL);
    struct tm tmv;
    char buf[16];
    localtime_r(&t, &tmv);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    printf("[%s] ", buf);
}

/* Walks every entry currently in ue_state_map -- the real kernel hash-map
 * iteration protocol (bpf_map_get_next_key() + bpf_map_lookup_elem()),
 * same as test_map_walk.c's walk_nodes()/walk_edges() in map_test.md.
 * Each entry is (source IPv4, FSM state, how long ago it was last
 * updated). This is the real, live version of "distinguish SCTP and
 * HTTP": only sources amf_xdp_enforce() actually categorized as NGAP ever
 * show up here at all -- an HTTP client hammering the same interface
 * never will. */
static void dump_ue_state_map(int ue_fd)
{
    uint32_t key = 0, next_key;
    int have_key = 0;
    int printed = 0;
    uint64_t now = now_ns();

    printf("  ue_state_map:\n");
    while (bpf_map_get_next_key(ue_fd, have_key ? &key : NULL, &next_key) == 0) {
        struct ue_val val;
        if (bpf_map_lookup_elem(ue_fd, &next_key, &val) == 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_key, ip, sizeof(ip));
            double age_s = (double)(now - val.last_seen_ns) / 1e9;
            printf("    %-15s state=%-24s last update %.1fs ago\n", ip, val.state, age_s);
            printed++;
        }
        key = next_key;
        have_key = 1;
    }
    if (!printed)
        printf("    (empty -- no SCTP/NGAP traffic categorized yet)\n");
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : DEFAULT_IFACE;

    require_root(argc > 0 ? argv[0] : "test_xdp"); /* attaching XDP + reading BPF maps both need real BPF/net privileges */

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "test_xdp: no such interface \"%s\": %s\n", ifname, strerror(errno));
        return 1;
    }

    printf("[*] Loading %s...\n", XDP_OBJ_PATH);
    struct bpf_object *obj = bpf_object__open_file(XDP_OBJ_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "test_xdp: bpf_object__open_file(%s): %s (did you run `make` first?)\n",
                XDP_OBJ_PATH, strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "test_xdp: bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog      = bpf_object__find_program_by_name(obj, XDP_PROG_NAME);
    struct bpf_map     *nodes_map = bpf_object__find_map_by_name(obj, "sm_nodes");
    struct bpf_map     *edges_map = bpf_object__find_map_by_name(obj, "sm_edges");
    struct bpf_map     *stats_map = bpf_object__find_map_by_name(obj, "amf_xdp_stats");
    struct bpf_map     *ue_map    = bpf_object__find_map_by_name(obj, "ue_state_map");
    if (!prog || !nodes_map || !edges_map || !stats_map || !ue_map) {
        fprintf(stderr, "test_xdp: missing expected program/map in %s -- did ../amf_xdp.c change?\n",
                XDP_OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd  = bpf_program__fd(prog);
    int nodes_fd = bpf_map__fd(nodes_map);
    int edges_fd = bpf_map__fd(edges_map);
    int stats_fd = bpf_map__fd(stats_map);
    int ue_fd    = bpf_map__fd(ue_map);

    /* Unconditional, idempotent upsert (BPF_ANY) of the real 29-node/
     * 52-edge FSM table -- mirrors amf_loader.c's sm_map_populate(),
     * which runs every time amf_loader starts regardless of whether
     * sm_nodes/sm_edges were just freshly created by the
     * bpf_object__load() above (first BPF object on the box to touch
     * them) or already existed (a real amf_loader is running too). */
    printf("[*] Loading state machine (sm_nodes/sm_edges)...\n");
    if (fx_populate_nodes(nodes_fd) != 0 || fx_populate_edges(edges_fd) != 0) {
        fprintf(stderr, "test_xdp: failed to populate sm_nodes/sm_edges\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Generic/SKB mode: works on any interface, including a veth pair,
     * without needing native driver-level XDP support -- the same
     * portability tradeoff ../README.md's own `ip link set ... xdp`
     * command makes implicitly. XDP_FLAGS_UPDATE_IF_NOEXIST makes
     * bpf_xdp_attach() FAIL instead of silently replacing whatever is
     * already attached (e.g. a real production amf_xdp.o), so this
     * monitor can never accidentally steal the program out from under a
     * real running deployment. */
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    printf("[*] Attaching %s to %s (ifindex %u, generic/SKB mode)...\n",
           XDP_PROG_NAME, ifname, ifindex);
    if (bpf_xdp_attach((int)ifindex, prog_fd, xdp_flags, NULL) != 0) {
        fprintf(stderr, "test_xdp: bpf_xdp_attach(%s): %s\n", ifname, strerror(errno));
        fprintf(stderr, "    (something already attached? try: sudo ip link set dev %s xdp off)\n", ifname);
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\n[*] Watching %s. Send it real SCTP/NGAP and HTTP traffic and compare.\n", ifname);
    printf("[*] Ctrl+C to detach and exit.\n\n");

    uint64_t last[STAT_MAX] = {0};
    while (!g_stop) {
        sleep(1); /* interrupted early (EINTR) by Ctrl+C -- the `while (!g_stop)` check below catches that */
        if (g_stop)
            break;

        uint64_t cur[STAT_MAX];
        int changed = 0;
        for (uint32_t idx = 0; idx < STAT_MAX; idx++) {
            cur[idx] = 0;
            bpf_map_lookup_elem(stats_fd, &idx, &cur[idx]); /* leaves cur[idx]==0 on a (shouldn't-happen) miss */
            if (cur[idx] != last[idx])
                changed = 1;
        }

        if (!changed)
            continue; /* nothing moved since the last tick -- stay quiet instead of spamming a heartbeat every second */

        print_ts();
        for (uint32_t idx = 0; idx < STAT_MAX; idx++) {
            printf("%s=%llu(+%llu) ", stat_name[idx],
                   (unsigned long long)cur[idx],
                   (unsigned long long)(cur[idx] - last[idx]));
        }
        printf("\n");
        dump_ue_state_map(ue_fd);

        memcpy(last, cur, sizeof(last));
    }

    printf("\n[*] Detaching from %s...\n", ifname);
    if (bpf_xdp_detach((int)ifindex, xdp_flags, NULL) != 0)
        fprintf(stderr, "test_xdp: bpf_xdp_detach(%s): %s\n", ifname, strerror(errno));

    bpf_object__close(obj); /* closes prog_fd + every map fd this object owns */
    return 0;
}
