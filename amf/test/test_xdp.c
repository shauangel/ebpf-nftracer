/*
 * test_xdp.c — small live monitor for ../amf_xdp.c.
 *
 * Loads the real, compiled amf_xdp.o, attaches amf_xdp_enforce() as an
 * actual XDP program on a real network interface (default: veth5538fab,
 * ../amf_xdp.c's own documented attach target), then once a second
 * prints amf_xdp_stats (PASS/DROP/STATE_INVALID) and dumps ue_state_map.
 *
 * Alongside that, this file ALSO runs its own independent, userspace
 * SCTP/NGAP packet sniffer (see parse_and_print_sctp_ngap() below) --
 * the exact same recognition logic ../xdp_ngap.c's proven-working
 * xdp_prog() uses (same constants: IPPROTO_SCTP, SCTP_PPID_NGAP,
 * SCTP_DATA; same Ethernet -> IPv4 -> SCTP -> DATA chunk -> NGAP
 * procedureCode walk), just run over an AF_PACKET/SOCK_RAW capture
 * instead of as an attached BPF program. This gives an independent,
 * BPF-free confirmation of whether real SCTP/NGAP packets are actually
 * arriving and parsing correctly on the wire, with nothing in common
 * with amf_xdp.c's own (possibly buggy) categorization/FSM pipeline --
 * if this sniffer sees a packet but amf_xdp_stats never moves, the
 * problem is specifically in amf_xdp.c's pipeline, not in the raw
 * packet shape.
 *
 * This also runs a check every tick to make sure amf_xdp_enforce() is
 * STILL the program attached -- not just that the interface still
 * exists. That distinction turned out to matter: an interface being
 * destroyed and recreated (e.g. a container restart) is one way to lose
 * an XDP attachment, but NOT the only way -- something can also
 * explicitly detach/replace the program while the device itself is
 * untouched (`ip link set dev X xdp off`, another tool attaching its own
 * program, a network-management daemon resetting link state). An
 * earlier version of this file only checked the interface's ifindex, so
 * exactly that second case showed up as "it detached after a few
 * minutes with no alert printed" -- the ifindex never changed, so that
 * check never fired, and amf_xdp_stats simply stopped moving because the
 * program silently wasn't in the datapath anymore. verify_attachment()
 * below checks both.
 *
 * bpf_printk() output (amf_xdp.c's existing FSM-mismatch/rate-limit
 * traces) is streamed live via the kernel trace pipe instead of
 * requiring a second `sudo cat /sys/kernel/debug/tracing/trace_pipe` in
 * another terminal.
 *
 * Usage:
 *   sudo ./test_xdp [ifname]     # default: veth5538fab
 *   ^C to detach and exit.
 *
 * Requires: Linux + CONFIG_BPF_SYSCALL, libbpf (bpf_xdp_attach()/
 * bpf_xdp_detach()/bpf_xdp_query(), i.e. libbpf >= 0.6), root (attaching
 * an XDP program, opening an AF_PACKET socket, and reading BPF maps all
 * need real privileges), the named interface to already exist, and
 * amf_xdp.o already built (`make` in this directory). See
 * doc_xdp_test.md for a full walkthrough.
 */

/* Must come before ANY system header: with -std=c11 (strict ISO C, see
 * this directory's Makefile), glibc's <time.h> hides CLOCK_MONOTONIC/
 * clock_gettime() (POSIX.1b real-time extensions) and <time.h>/<net/if.h>
 * hide localtime_r()/if_nametoindex() unless a feature-test macro asks
 * for POSIX explicitly -- unlike close()/unlink() etc. (POSIX baseline,
 * exposed regardless), these need _POSIX_C_SOURCE >= 199309L. 200809L
 * (POSIX.1-2008) covers all of them at once. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>       /* inet_ntop()/INET_ADDRSTRLEN/htons()/ntohs()/ntohl() */
#include <net/if.h>          /* if_nametoindex() -- interface name -> ifindex */
#include <linux/if_link.h>   /* XDP_FLAGS_* -- attach-mode flags for bpf_xdp_attach()/bpf_xdp_query() */
#include <linux/if_packet.h> /* struct sockaddr_ll -- for the raw AF_PACKET sniffer */
#include <sys/socket.h>      /* socket()/bind()/recv(), AF_PACKET/SOCK_RAW */

#include <bpf/bpf.h>     /* bpf_map_lookup_elem()/bpf_map_get_next_key()/bpf_obj_get_info_by_fd() -- real bpf() syscalls */
#include <bpf/libbpf.h>  /* bpf_object__open_file/load, bpf_xdp_attach/detach/query, find_program/map_by_name */

#include "test_util.h"  /* require_root() */
#include "fixtures.h"   /* fx_populate_nodes()/fx_populate_edges() -- the real 29/52-entry FSM table */
#include "../sm_map.h"  /* SM_NAME_MAX -- ue_state_map's state field is this size, see struct ue_val below */

#define XDP_OBJ_PATH      "amf_xdp.o"       /* built by this directory's Makefile */
#define XDP_PROG_NAME     "amf_xdp_enforce" /* the SEC("xdp") function's C name in ../amf_xdp.c */
#define DEFAULT_IFACE     "veth5538fab"     /* ../amf_xdp.c's own documented attach target; override via argv[1] */
#define TRACE_PIPE_PATH_1 "/sys/kernel/debug/tracing/trace_pipe" /* classic debugfs mount point */
#define TRACE_PIPE_PATH_2 "/sys/kernel/tracing/trace_pipe"       /* tracefs, when debugfs isn't mounted */

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

/* ── mirrors of ../xdp_ngap.c's parsing constants/structs ───────────────
 * ../xdp_ngap.c is left completely unmodified (per instructions) -- this
 * is a copy of its "main code" (the recognition logic inside xdp_prog(),
 * see that file), adapted to run over a plain userspace byte buffer
 * (parse_and_print_sctp_ngap() below) instead of an XDP ctx->data/
 * ctx->data_end pair. Keep in sync with ../xdp_ngap.c by inspection. */
#define RAW_ETH_P_ALL      0x0003 /* AF_PACKET wildcard protocol -- capture every frame, not just IP */
#define RAW_ETH_P_IP       0x0800 /* == xdp_ngap.c's ETH_P_IP */
#define RAW_IPPROTO_SCTP   132    /* == xdp_ngap.c's IPPROTO_SCTP */
#define RAW_SCTP_PPID_NGAP 60     /* == xdp_ngap.c's SCTP_PPID_NGAP */
#define RAW_SCTP_DATA      0      /* == xdp_ngap.c's SCTP_DATA */

struct sctphdr_simple {
    uint16_t source;
    uint16_t dest;
    uint32_t vtag;
    uint32_t checksum;
} __attribute__((packed));

struct sctp_data_chunk {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_seq;
    uint32_t ppid;
} __attribute__((packed));

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_stop_signal; /* which signal set g_stop -- see the SIGINT/SIGTERM print near main()'s cleanup */
static void handle_signal(int sig) { g_stop = 1; g_stop_signal = sig; }

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

/* ── kernel trace pipe streaming ──────────────────────────────────────
 * bpf_printk() (used by ../amf_xdp.c's existing FSM-mismatch/rate-limit
 * traces) writes to a shared, system-wide ring buffer exposed as this
 * file -- there is no per-program filtering, so anything else on the box
 * calling bpf_printk() shows up here too, and only one reader gets each
 * line (racy if something else, e.g. a manual `cat`, is also reading
 * it). Good enough for a debug monitor. Opened O_NONBLOCK so draining it
 * fits into the same once-a-second poll loop as everything else below,
 * without needing a second thread. */
static int g_trace_fd = -1;

static void open_trace_pipe(void)
{
    g_trace_fd = open(TRACE_PIPE_PATH_1, O_RDONLY | O_NONBLOCK);
    if (g_trace_fd < 0)
        g_trace_fd = open(TRACE_PIPE_PATH_2, O_RDONLY | O_NONBLOCK);
    if (g_trace_fd < 0) {
        fprintf(stderr,
                "test_xdp: could not open the kernel trace pipe (%s): bpf_printk output won't\n"
                "    show up here -- view it separately with:\n"
                "    sudo cat %s\n",
                strerror(errno), TRACE_PIPE_PATH_1);
    }
}

static void drain_trace_pipe(void)
{
    if (g_trace_fd < 0)
        return;
    char buf[4096];
    ssize_t n;
    /* Non-blocking: reads whatever is already buffered and stops at
     * EAGAIN, rather than waiting for more -- this is not a full
     * line-reassembly reader (a line spanning two read()s can print
     * split across two calls), which is an acceptable tradeoff for a
     * debug trace, not a log parser. */
    while ((n = read(g_trace_fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);
    }
}

/* ── raw userspace SCTP/NGAP sniffer ───────────────────────────────────
 * Independent of the attached amf_xdp_enforce() program entirely: an
 * AF_PACKET/SOCK_RAW socket bound to the interface, capturing every
 * frame it sees, like a minimal single-purpose tcpdump. */
static int g_raw_fd = -1;

static int open_raw_sniffer(const char *ifname, unsigned int ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(RAW_ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "test_xdp: socket(AF_PACKET): %s (raw sniffer disabled)\n", strerror(errno));
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(RAW_ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        fprintf(stderr, "test_xdp: bind(AF_PACKET, %s): %s (raw sniffer disabled)\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

/* One packet's worth of the exact recognition chain ../xdp_ngap.c's
 * xdp_prog() runs (Ethernet -> IPv4 -> SCTP -> DATA chunk -> NGAP
 * procedureCode), just walked over a plain captured byte buffer instead
 * of ctx->data/ctx->data_end. Prints the same fields xdp_ngap.c's
 * bpf_printk() line does whenever every check passes; silently ignores
 * any frame that fails a check, exactly like xdp_prog() falling through
 * to XDP_PASS at each one. */
static void parse_and_print_sctp_ngap(const unsigned char *buf, ssize_t len)
{
    const unsigned char *end = buf + len;

    if (buf + 14 > end)                                   /* Ethernet header (dst[6]+src[6]+ethertype[2]) */
        return;
    uint16_t ethertype = (uint16_t)((buf[12] << 8) | buf[13]);
    if (ethertype != RAW_ETH_P_IP)
        return;

    const unsigned char *iph = buf + 14;
    if (iph + 20 > end)                                    /* IPv4 header, minimum 20 bytes (no options) */
        return;
    uint8_t ihl      = iph[0] & 0x0F;                       /* low nibble of the first byte, header length in 32-bit words */
    uint8_t protocol = iph[9];                              /* IPv4 header's protocol field */
    if (protocol != RAW_IPPROTO_SCTP)
        return;

    const unsigned char *sctp_ptr = iph + (ihl * 4);        /* IP header length may be > 20 bytes */
    if (sctp_ptr + sizeof(struct sctphdr_simple) > end)
        return;
    struct sctphdr_simple sctp;
    memcpy(&sctp, sctp_ptr, sizeof(sctp));

    const unsigned char *chunk_ptr = sctp_ptr + sizeof(struct sctphdr_simple);
    if (chunk_ptr + sizeof(struct sctp_data_chunk) > end)
        return;
    struct sctp_data_chunk chunk;
    memcpy(&chunk, chunk_ptr, sizeof(chunk));

    if (chunk.type != RAW_SCTP_DATA)
        return;
    uint32_t ppid = ntohl(chunk.ppid);
    if (ppid != RAW_SCTP_PPID_NGAP)
        return;

    /* NGAP PDU: first two bytes are the procedureCode. */
    const unsigned char *ngap = chunk_ptr + sizeof(struct sctp_data_chunk);
    if (ngap + 2 > end)
        return;
    uint16_t procedure_code = (uint16_t)((ngap[0] << 8) | ngap[1]);

    print_ts();
    printf("[raw-sniff] SCTP sport=%u dport=%u len=%u NGAP-procedureCode=%u\n",
           ntohs(sctp.source), ntohs(sctp.dest), ntohs(chunk.length), procedure_code);
}

static void drain_raw_sniffer(void)
{
    if (g_raw_fd < 0)
        return;
    unsigned char buf[2048];
    ssize_t n;
    while ((n = recv(g_raw_fd, buf, sizeof(buf), 0)) > 0)
        parse_and_print_sctp_ngap(buf, n);
}

/* Walks every entry currently in ue_state_map -- the real kernel hash-map
 * iteration protocol (bpf_map_get_next_key() + bpf_map_lookup_elem()),
 * same as test_map_walk.c's walk_nodes()/walk_edges() in doc_map_test.md.
 * Each entry is (source IPv4, FSM state, how long ago it was last
 * updated). */
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

enum attach_check_result { ATTACH_OK, ATTACH_REATTACHED, ATTACH_LOST };

/* Checks TWO independent ways this process's XDP attachment can go away,
 * and self-heals the first one:
 *
 *  1. The interface itself was destroyed and (maybe) recreated. An XDP
 *     attachment lives on the kernel net_device, not the interface NAME
 *     -- if whatever owns this veth tears it down (by far the most
 *     common trigger: a container that owns the other end restarting,
 *     e.g. an AMF/gNB container restarting as part of bringing up a UE
 *     simulator), the attachment is destroyed right along with the old
 *     device. Detected by *ifindex changing (device replaced) or going
 *     to 0 (device gone entirely).
 *
 *  2. The SAME device is still there, but something explicitly detached
 *     or replaced the program on it (`ip link set dev X xdp off`,
 *     another attach call, a network-management daemon resetting link
 *     state) without touching the interface object itself. Case (1)'s
 *     ifindex check does NOT catch this -- it needs an actual query of
 *     which program (if any) is currently attached, compared against
 *     our own program's id. This is the case that used to go completely
 *     unreported: the device looked unchanged, so nothing fired, and
 *     amf_xdp_stats just quietly stopped moving. */
static enum attach_check_result verify_attachment(const char *ifname, unsigned int *ifindex,
                                                    int prog_fd, uint32_t our_prog_id,
                                                    __u32 xdp_flags)
{
    unsigned int cur_ifindex = if_nametoindex(ifname);

    if (cur_ifindex == 0) {
        print_ts();
        printf("interface \"%s\" no longer exists (was ifindex %u).\n", ifname, *ifindex);
        printf("    Something outside this process removed it -- most likely a container\n");
        printf("    (AMF/gNB/UE-simulator) that owns the other end of this veth was\n");
        printf("    restarted, which destroys the whole device. There is nothing left here\n");
        printf("    to detach. Re-run test_xdp once \"%s\" exists again.\n", ifname);
        return ATTACH_LOST;
    }

    if (cur_ifindex != *ifindex) {
        print_ts();
        printf("interface \"%s\" was recreated (ifindex %u -> %u) -- re-attaching...\n",
               ifname, *ifindex, cur_ifindex);
        *ifindex = cur_ifindex;
        if (bpf_xdp_attach((int)*ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "    re-attach failed: %s\n", strerror(errno));
            return ATTACH_LOST;
        }
        printf("    re-attached to ifindex %u.\n", *ifindex);
        return ATTACH_REATTACHED;
    }

    struct bpf_xdp_query_opts qopts;
    memset(&qopts, 0, sizeof(qopts));
    qopts.sz = sizeof(qopts);
    uint32_t attached_id = 0;
    if (bpf_xdp_query((int)*ifindex, XDP_FLAGS_SKB_MODE, &qopts) == 0)
        attached_id = qopts.skb_prog_id; /* we always attach in generic/SKB mode -- see xdp_flags below */

    if (attached_id != our_prog_id) {
        print_ts();
        if (attached_id == 0) {
            printf("XDP program is no longer attached to \"%s\" (device unchanged, ifindex %u) --\n",
                   ifname, *ifindex);
            printf("    something explicitly detached it (`ip link set dev %s xdp off`, or a\n", ifname);
            printf("    network-management tool/script resetting link state). Re-attaching...\n");
        } else {
            printf("a DIFFERENT XDP program (id %u) is now attached to \"%s\" -- ours (id %u)\n",
                   attached_id, ifname, our_prog_id);
            printf("    was replaced. Re-attaching...\n");
        }
        if (bpf_xdp_attach((int)*ifindex, prog_fd, xdp_flags, NULL) != 0) {
            fprintf(stderr, "    re-attach failed: %s\n", strerror(errno));
            return ATTACH_LOST;
        }
        printf("    re-attached (prog id %u).\n", our_prog_id);
        return ATTACH_REATTACHED;
    }

    return ATTACH_OK;
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : DEFAULT_IFACE;

    require_root(argc > 0 ? argv[0] : "test_xdp"); /* attaching XDP, raw sockets, and reading BPF maps all need real privileges */

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

    /* Our own program's id, so verify_attachment() can tell "still ours"
     * apart from "something else is attached now". */
    struct bpf_prog_info prog_info;
    memset(&prog_info, 0, sizeof(prog_info));
    uint32_t prog_info_len = sizeof(prog_info);
    if (bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_info_len) != 0) {
        fprintf(stderr, "test_xdp: bpf_obj_get_info_by_fd(prog): %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    uint32_t our_prog_id = prog_info.id;

    open_trace_pipe();
    int raw_fd = open_raw_sniffer(ifname, ifindex);
    g_raw_fd = raw_fd;

    /* Generic/SKB mode: works on any interface, including a veth pair,
     * without needing native driver-level XDP support -- the same
     * portability tradeoff ../README.md's own `ip link set ... xdp`
     * command makes implicitly. XDP_FLAGS_UPDATE_IF_NOEXIST makes
     * bpf_xdp_attach() FAIL instead of silently replacing whatever is
     * already attached (e.g. a real production amf_xdp.o), so this
     * monitor can never accidentally steal the program out from under a
     * real running deployment. */
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    printf("[*] Attaching %s to %s (ifindex %u, generic/SKB mode, prog id %u)...\n",
           XDP_PROG_NAME, ifname, ifindex, our_prog_id);
    if (bpf_xdp_attach((int)ifindex, prog_fd, xdp_flags, NULL) != 0) {
        fprintf(stderr, "test_xdp: bpf_xdp_attach(%s): %s\n", ifname, strerror(errno));
        fprintf(stderr, "    (something already attached? try: sudo ip link set dev %s xdp off)\n", ifname);
        if (g_trace_fd >= 0) close(g_trace_fd);
        if (g_raw_fd   >= 0) close(g_raw_fd);
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\n[*] Watching %s. Send it real SCTP/NGAP and HTTP traffic and compare.\n", ifname);
    if (g_raw_fd >= 0)
        printf("[*] Also independently sniffing raw SCTP/NGAP traffic (prefixed \"[raw-sniff]\").\n");
    printf("[*] Ctrl+C to detach and exit.\n\n");

    int iface_lost = 0;
    uint64_t last[STAT_MAX] = {0};

    while (!g_stop) {
        sleep(1); /* interrupted early (EINTR) by Ctrl+C -- the `while (!g_stop)` check below catches that */
        if (g_stop)
            break;

        drain_trace_pipe();
        drain_raw_sniffer();

        enum attach_check_result r = verify_attachment(ifname, &ifindex, prog_fd, our_prog_id, xdp_flags);
        if (r == ATTACH_LOST) {
            iface_lost = 1;
            break;
        }

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

    drain_trace_pipe();  /* catch any last lines before we detach */
    drain_raw_sniffer();

    if (g_trace_fd >= 0) close(g_trace_fd);
    if (g_raw_fd   >= 0) close(g_raw_fd);

    if (iface_lost) {
        /* Nothing to detach -- see the diagnostic already printed above
         * (either the interface is gone entirely, or we failed to
         * re-attach to its replacement). */
        bpf_object__close(obj);
        return 1;
    }

    printf("\n[*] Received signal %d (%s) -- detaching from %s...\n",
           (int)g_stop_signal, strsignal((int)g_stop_signal), ifname);
    if (bpf_xdp_detach((int)ifindex, xdp_flags, NULL) != 0)
        fprintf(stderr, "test_xdp: bpf_xdp_detach(%s): %s\n", ifname, strerror(errno));

    bpf_object__close(obj); /* closes prog_fd + every map fd this object owns */
    return 0;
}
