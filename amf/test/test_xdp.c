/*
 * test_xdp.c — loads the REAL amf_xdp.o (compiled from ../amf_xdp.c) and
 * drives it with the kernel's BPF_PROG_TEST_RUN facility against
 * hand-built raw packets. No veth, no network namespace, no real NIC:
 * BPF_PROG_TEST_RUN hands a byte buffer straight to the loaded program as
 * if it were `ctx->data`/`ctx->data_end` and reports back the program's
 * real return value (XDP_PASS/XDP_DROP/...) -- the same technique the
 * kernel's own BPF selftests use to test XDP programs in isolation.
 *
 * Primary thing under test: amf_xdp_enforce() must be able to tell an
 * SCTP/NGAP packet (the only traffic it's meant to inspect) apart from
 * ordinary HTTP-over-TCP traffic (which must sail through completely
 * untouched, fail-open, per the file header comment in ../amf_xdp.c). We
 * verify this two ways, not just the return code: after an SCTP/NGAP
 * InitialUEMessage, amf_xdp_stats/ue_state_map must show it was
 * processed; after an HTTP packet, both maps must be BYTE-FOR-BYTE
 * unchanged from right before it -- proving the early
 * `iph->protocol != IPPROTO_SCTP` check truly short-circuits before any
 * categorization/FSM/stat code runs, not just that XDP_PASS happens to
 * come out both times for different reasons.
 *
 * sm_nodes/sm_edges: amf_xdp.o embeds sm_map.c, which pins these two maps
 * (see ../sm_map.c). Loading amf_xdp.o here will create+pin them if this
 * is the first BPF object on the box to touch them, exactly like
 * ../README.md describes -- we then (re)populate them ourselves with the
 * real fixtures.h table so the FSM half of amf_xdp_enforce() has real
 * data to check against regardless of prior system state. This mirrors
 * amf_loader.c's own sm_map_populate() call, which is an unconditional,
 * idempotent upsert (BPF_ANY) every time amf_loader starts.
 *
 * Requires: Linux + CONFIG_BPF_SYSCALL, libbpf (with
 * bpf_prog_test_run_opts(), i.e. a reasonably recent libpf -- same
 * baseline the rest of this suite already assumes), clang (to build
 * amf_xdp.o -- see the Makefile), and root. See xdp_test.md for a full
 * line-by-line walkthrough.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>  /* htons()/htonl() -- network byte order for the packet headers we build */

#include <bpf/bpf.h>     /* bpf_map_lookup_elem(), bpf_prog_test_run_opts() -- real bpf() syscalls */
#include <bpf/libbpf.h>  /* bpf_object__open_file/load, find_program/map_by_name, bpf_program__fd, bpf_map__fd */

#include "framework.h"  /* CHECK()/RUN_TEST()/test_summary() */
#include "test_util.h"  /* require_root() */
#include "fixtures.h"   /* fx_populate_nodes()/fx_populate_edges() -- the real 29/52-entry FSM table */
#include "../sm_map.h"  /* SM_NAME_MAX -- ue_state_map's state field is this size, see struct ue_val below */

/* Built by this directory's Makefile (`clang -target bpf ... -c
 * ../amf_xdp.c -o amf_xdp.o`); ../amf_xdp.c has never had a Makefile rule
 * of its own (see its header comment -- it's historically hand-compiled),
 * so amf/test/Makefile is the first place that automates building it,
 * and it builds it INTO amf/test/, not amf/. */
#define XDP_OBJ_PATH "amf_xdp.o"
#define XDP_PROG_NAME "amf_xdp_enforce"   /* the SEC("xdp") function's C name in ../amf_xdp.c */

/* ── mirrors of amf_xdp.c's PRIVATE constants/structs ─────────────────
 * None of these are in sm_map.h -- they're local to ../amf_xdp.c, which
 * we only ever load as a compiled .o, never #include as source. To build
 * wire-accurate test packets and to decode the raw bytes we read back out
 * of its maps, we need identical copies here. Keep in sync with
 * ../amf_xdp.c by inspection (same convention fixtures.h uses for
 * ../amf_comm.c's FSM table). */

#define TEST_ETH_P_IP                     0x0800  /* == amf_xdp.c's ETH_P_IP */
#define TEST_IPPROTO_SCTP                 132     /* == amf_xdp.c's IPPROTO_SCTP */
#define TEST_IPPROTO_TCP                  6        /* plain IANA TCP; amf_xdp.c has no #define for this since it never needs to name it -- anything != IPPROTO_SCTP takes the same fail-open path */
#define TEST_SCTP_PPID_NGAP               60       /* == amf_xdp.c's SCTP_PPID_NGAP */
#define TEST_SCTP_DATA_CHUNK_TYPE         0        /* == amf_xdp.c's SCTP_DATA */
#define TEST_NGAP_PROC_INITIAL_UE_MESSAGE 15       /* == amf_xdp.c's NGAP_PROC_INITIAL_UE_MESSAGE */

/* == amf_xdp.c's `enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };` */
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };

/* == amf_xdp.c's `struct ue_val { char state[SM_NAME_MAX]; __u64 last_seen_ns; };`
 * SM_NAME_MAX comes from sm_map.h (shared, real), so this struct's layout
 * is guaranteed to match ../amf_xdp.c's copy byte-for-byte. */
struct ue_val {
    char     state[SM_NAME_MAX];
    uint64_t last_seen_ns;
};

/* ── minimal, self-contained wire-format structs for building test packets ──
 * Deliberately NOT <linux/if_ether.h>/<linux/ip.h>/<netinet/tcp.h> --
 * mixing linux and netinet network headers in the same translation unit
 * is a well-known source of duplicate-definition build errors, and their
 * bitfield-based version/ihl and data-offset fields are byte-order-
 * dependent in a way this file has no need to reason about. Instead:
 * every multi-bit-field byte (IP's version+IHL, TCP's data-offset) is
 * written as a single already-packed literal (0x45, 0x50) -- the actual
 * ON-THE-WIRE byte value per RFC 791/793, true on any host regardless of
 * that host's own bitfield packing order. */

struct test_ethhdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;   /* network byte order */
} __attribute__((packed));

struct test_iphdr {
    uint8_t  ihl_version; /* 0x45 = version 4, IHL 5 (20-byte header, no options) -- see comment above */
    uint8_t  tos;
    uint16_t tot_len;     /* network byte order */
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;    /* the ONE field amf_xdp_enforce() branches on: IPPROTO_SCTP vs. anything else */
    uint16_t check;
    uint32_t saddr;       /* network byte order -- becomes amf_xdp.c's src_ip / ue_state_map key */
    uint32_t daddr;       /* network byte order */
} __attribute__((packed));

/* Mirrors ../amf_xdp.c's struct sctphdr_simple byte-for-byte. */
struct test_sctphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t vtag;
    uint32_t checksum;
} __attribute__((packed));

/* Mirrors ../amf_xdp.c's struct sctp_data_chunk byte-for-byte. */
struct test_sctp_data_chunk {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_seq;
    uint32_t ppid;
} __attribute__((packed));

struct test_tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_reserved; /* 0x50 = data offset 5 (20-byte header, no options), reserved bits 0 */
    uint8_t  flags;         /* 0x18 = PSH|ACK, i.e. "here is some data", like a real GET request */
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

/* ── packet builders ─────────────────────────────────────────────────── */

/* Builds a full Ethernet/IPv4/SCTP/NGAP frame carrying a single DATA
 * chunk whose payload's first two bytes are procedureCode=15
 * (id-InitialUEMessage) -- exactly what a real gNB's InitialUEMessage
 * looks like at the byte level amf_xdp_enforce() actually reads. Writes
 * the source IP (used as amf_xdp.c's ue_state_map/rate-map key) out
 * through *src_ip_out so the caller can look it up afterward. Returns the
 * total frame length. */
static size_t build_sctp_ngap_initial_ue_message(unsigned char *buf, size_t buf_len,
                                                   uint32_t *src_ip_out)
{
    unsigned char *p = buf;

    /* MAC addresses are never inspected by amf_xdp_enforce() -- any
     * locally-administered-looking bytes will do. */
    struct test_ethhdr eth = {
        .dst = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .src = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        .ethertype = htons(TEST_ETH_P_IP),
    };

    uint32_t src_ip = htonl(0x0A000005); /* 10.0.0.5 -- stands in for "the gNB" */
    uint32_t dst_ip = htonl(0x0A000001); /* 10.0.0.1 -- stands in for "the AMF's N2 address" */

    struct test_sctphdr sctp = {
        .source   = htons(38412), /* NGAP's IANA-assigned SCTP port, for realism -- not checked by amf_xdp.c */
        .dest     = htons(38412),
        .vtag     = 0,
        .checksum = 0,             /* amf_xdp.c never validates the SCTP checksum */
    };

    struct test_sctp_data_chunk chunk = {
        .type       = TEST_SCTP_DATA_CHUNK_TYPE,
        .flags      = 0,
        .length     = 0,                             /* not checked by amf_xdp.c */
        .tsn        = 0,
        .stream_id  = 0,
        .stream_seq = 0,
        .ppid       = htonl(TEST_SCTP_PPID_NGAP),     /* amf_xdp.c reads this with bpf_ntohl() */
    };

    /* First 2 bytes = procedureCode (big-endian, per amf_xdp.c's raw
     * `(b0 << 8) | b1` read); the remaining 14 bytes just pad out to 16
     * so amf_xdp.c's `ngap + 16 > data_end` bounds check passes -- their
     * content is otherwise never read. */
    unsigned char ngap[16] = { 0x00, TEST_NGAP_PROC_INITIAL_UE_MESSAGE };

    size_t ip_payload_len = sizeof(sctp) + sizeof(chunk) + sizeof(ngap);
    struct test_iphdr iph = {
        .ihl_version = 0x45,
        .tos         = 0,
        .tot_len     = htons((uint16_t)(sizeof(struct test_iphdr) + ip_payload_len)),
        .id          = 0,
        .frag_off    = 0,
        .ttl         = 64,
        .protocol    = TEST_IPPROTO_SCTP,   /* <-- makes this packet "visible" to amf_xdp_enforce() */
        .check       = 0,
        .saddr       = src_ip,
        .daddr       = dst_ip,
    };

    memcpy(p, &eth,   sizeof(eth));   p += sizeof(eth);
    memcpy(p, &iph,   sizeof(iph));   p += sizeof(iph);
    memcpy(p, &sctp,  sizeof(sctp));  p += sizeof(sctp);
    memcpy(p, &chunk, sizeof(chunk)); p += sizeof(chunk);
    memcpy(p, ngap,   sizeof(ngap));  p += sizeof(ngap);

    *src_ip_out = src_ip;
    size_t total = (size_t)(p - buf);
    CHECK(total <= buf_len); /* buffer sizing bug in this helper, not something amf_xdp.c did wrong */
    return total;
}

/* Builds a full Ethernet/IPv4/TCP frame carrying a literal HTTP GET
 * request -- ordinary web traffic that has nothing to do with the AMF's
 * N2 interface. amf_xdp_enforce() is expected to bail out at the very
 * first `iph->protocol != IPPROTO_SCTP` check and never look at any of
 * the TCP/HTTP bytes below at all. */
static size_t build_http_get_request(unsigned char *buf, size_t buf_len, uint32_t *src_ip_out)
{
    unsigned char *p = buf;

    struct test_ethhdr eth = {
        .dst = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .src = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x03 },
        .ethertype = htons(TEST_ETH_P_IP),
    };

    uint32_t src_ip = htonl(0x0A000006); /* 10.0.0.6 -- a plain host, unrelated to any gNB/UE */
    uint32_t dst_ip = htonl(0x0A000001);

    static const char http_get[] = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    size_t http_len = sizeof(http_get) - 1; /* drop the implicit NUL terminator */

    struct test_tcphdr tcp = {
        .source         = htons(51000),
        .dest           = htons(80),   /* the detail that makes this recognizably "HTTP" to a human reading the capture */
        .seq            = 0,
        .ack_seq        = 0,
        .doff_reserved  = 0x50,
        .flags          = 0x18,
        .window         = htons(65535),
        .check          = 0,
        .urg_ptr        = 0,
    };

    size_t ip_payload_len = sizeof(tcp) + http_len;
    struct test_iphdr iph = {
        .ihl_version = 0x45,
        .tos         = 0,
        .tot_len     = htons((uint16_t)(sizeof(struct test_iphdr) + ip_payload_len)),
        .id          = 0,
        .frag_off    = 0,
        .ttl         = 64,
        .protocol    = TEST_IPPROTO_TCP,   /* <-- NOT IPPROTO_SCTP: amf_xdp_enforce() must stop here */
        .check       = 0,
        .saddr       = src_ip,
        .daddr       = dst_ip,
    };

    memcpy(p, &eth, sizeof(eth));       p += sizeof(eth);
    memcpy(p, &iph, sizeof(iph));       p += sizeof(iph);
    memcpy(p, &tcp, sizeof(tcp));       p += sizeof(tcp);
    memcpy(p, http_get, http_len);      p += http_len;

    *src_ip_out = src_ip;
    size_t total = (size_t)(p - buf);
    CHECK(total <= buf_len);
    return total;
}

/* ── BPF_PROG_TEST_RUN wrapper ────────────────────────────────────────
 * Hands `pkt`/`len` to the loaded XDP program exactly as if it had
 * arrived on a real NIC, and returns the program's actual return value
 * (XDP_PASS/XDP_DROP/...). data_out/data_size_out are supplied (even
 * though amf_xdp_enforce() never mutates a packet) because some kernel
 * versions expect a real output buffer whenever data_in is set -- 4096
 * bytes is comfortably larger than anything we send in. No ctx_in is
 * passed: leaving it NULL tells the kernel to derive the xdp_md's
 * data/data_end purely from data_in/data_size_in, which is all this
 * program's parsing logic (ctx->data/ctx->data_end only) needs. */
static uint32_t run_xdp_prog(int prog_fd, const unsigned char *pkt, size_t len)
{
    static unsigned char pkt_out[4096]; /* static: avoids putting 4KB on the stack per call */
    struct bpf_test_run_opts opts = {0};
    opts.sz            = sizeof(opts);
    opts.data_in       = pkt;
    opts.data_size_in  = (uint32_t)len;
    opts.data_out      = pkt_out;
    opts.data_size_out = sizeof(pkt_out);
    opts.repeat        = 1;

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    CHECK(err == 0);
    if (err) {
        fprintf(stderr, "    bpf_prog_test_run_opts: %s\n", strerror(errno));
        return (uint32_t)-1; /* not a real xdp_action -- caller's CHECK against XDP_PASS/DROP will simply fail */
    }
    return opts.retval;
}

/* ── tests ─────────────────────────────────────────────────────────────
 * The program/map fds are loaded once in main() and shared read-only by
 * every test below via these file-scope statics, since they all exercise
 * the SAME loaded amf_xdp_enforce() instance and its SAME maps (that's
 * the whole point -- e.g. the HTTP test's assertion that stats are
 * UNCHANGED only means something if it's checking the same stats map the
 * SCTP test just wrote to). */
static int g_prog_fd  = -1;
static int g_stats_fd = -1;
static int g_ue_fd    = -1;

static void test_stats_start_at_zero(void)
{
    /* amf_xdp_stats/ue_state_map are plain (unpinned) maps -- freshly
     * created by THIS process's bpf_object__load() call, never shared
     * with a prior run, so they must start completely empty/zeroed. */
    for (uint32_t idx = STAT_PASS; idx < STAT_MAX; idx++) {
        uint64_t v = (uint64_t)-1; /* poison value: a failed lookup must not silently read as "0" */
        CHECK(bpf_map_lookup_elem(g_stats_fd, &idx, &v) == 0);
        CHECK(v == 0);
    }
}

static void test_sctp_ngap_packet_is_categorized(void)
{
    unsigned char pkt[256];
    uint32_t src_ip;
    size_t len = build_sctp_ngap_initial_ue_message(pkt, sizeof(pkt), &src_ip);

    uint32_t retval = run_xdp_prog(g_prog_fd, pkt, len);
    printf("    SCTP/NGAP InitialUEMessage -> retval=%u (XDP_PASS=%d, XDP_DROP=%d)\n",
           retval, XDP_PASS, XDP_DROP);
    CHECK(retval == XDP_PASS); /* a single packet is nowhere near the 50/s rate limit */

    uint64_t stat;
    uint32_t idx = STAT_PASS;
    CHECK(bpf_map_lookup_elem(g_stats_fd, &idx, &stat) == 0 && stat == 1);
    idx = STAT_STATE_INVALID;
    /* Must be 0, not just "didn't crash": fixtures.h really does contain
     * the UE/gNB --InitialUEMessage--> REG_RECEIVED edge amf_xdp_enforce()
     * looks up for a never-before-seen source, so this must be a clean
     * FSM hit, not a mismatch that happened not to get dropped. */
    CHECK(bpf_map_lookup_elem(g_stats_fd, &idx, &stat) == 0 && stat == 0);

    struct ue_val ue = {0};
    CHECK(bpf_map_lookup_elem(g_ue_fd, &src_ip, &ue) == 0);
    CHECK_STREQ(ue.state, "REG_RECEIVED");
    printf("    ue_state_map[10.0.0.5] = \"%s\"\n", ue.state);
}

static void test_http_packet_is_not_categorized(void)
{
    unsigned char pkt[256];
    uint32_t src_ip;
    size_t len = build_http_get_request(pkt, sizeof(pkt), &src_ip);

    uint32_t retval = run_xdp_prog(g_prog_fd, pkt, len);
    printf("    HTTP GET over TCP        -> retval=%u (XDP_PASS=%d, XDP_DROP=%d)\n",
           retval, XDP_PASS, XDP_DROP);
    CHECK(retval == XDP_PASS); /* the fail-open early-return path, not the categorized-and-passed path */

    /* The crux of "distinguish SCTP from HTTP": these must be EXACTLY
     * what test_sctp_ngap_packet_is_categorized() already left them at
     * (STAT_PASS == 1), not incremented again -- proving this packet
     * never reached bump_stat() at all. */
    uint64_t stat;
    uint32_t idx = STAT_PASS;
    CHECK(bpf_map_lookup_elem(g_stats_fd, &idx, &stat) == 0 && stat == 1);
    idx = STAT_STATE_INVALID;
    CHECK(bpf_map_lookup_elem(g_stats_fd, &idx, &stat) == 0 && stat == 0);

    /* And no ue_state_map entry was ever created for this HTTP source --
     * amf_xdp_enforce() never even computed src_ip's FSM state. */
    struct ue_val ue = {0};
    CHECK(bpf_map_lookup_elem(g_ue_fd, &src_ip, &ue) != 0 && errno == ENOENT);
}

int main(int argc, char **argv)
{
    require_root(argc > 0 ? argv[0] : "test_xdp"); /* loading a BPF_PROG_TYPE_XDP program and running BPF_PROG_TEST_RUN both need real BPF privileges */

    printf("test_xdp:\n");

    struct bpf_object *obj = bpf_object__open_file(XDP_OBJ_PATH, NULL);
    CHECK(obj != NULL);
    if (!obj) {
        fprintf(stderr, "test_xdp: bpf_object__open_file(%s): %s "
                "(did you run `make` in amf/test first?)\n",
                XDP_OBJ_PATH, strerror(errno));
        return 1;
    }

    int err = bpf_object__load(obj);
    CHECK(err == 0);
    if (err) {
        fprintf(stderr, "test_xdp: bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, XDP_PROG_NAME);
    CHECK(prog != NULL);

    struct bpf_map *nodes_map = bpf_object__find_map_by_name(obj, "sm_nodes");
    struct bpf_map *edges_map = bpf_object__find_map_by_name(obj, "sm_edges");
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "amf_xdp_stats");
    struct bpf_map *ue_map    = bpf_object__find_map_by_name(obj, "ue_state_map");
    CHECK(nodes_map && edges_map && stats_map && ue_map);

    if (!prog || !nodes_map || !edges_map || !stats_map || !ue_map) {
        bpf_object__close(obj);
        return 1; /* can't proceed without every prog/map this file needs */
    }

    g_prog_fd  = bpf_program__fd(prog);
    g_stats_fd = bpf_map__fd(stats_map);
    g_ue_fd    = bpf_map__fd(ue_map);
    int nodes_fd = bpf_map__fd(nodes_map);
    int edges_fd = bpf_map__fd(edges_map);
    CHECK(g_prog_fd >= 0 && g_stats_fd >= 0 && g_ue_fd >= 0 && nodes_fd >= 0 && edges_fd >= 0);

    /* Unconditional, idempotent upsert of the real 29/52-entry FSM table
     * -- see the file header comment for why this is safe and correct
     * regardless of whether sm_nodes/sm_edges were just freshly created
     * by the bpf_object__load() above or already existed. */
    CHECK(fx_populate_nodes(nodes_fd) == 0);
    CHECK(fx_populate_edges(edges_fd) == 0);

    RUN_TEST(test_stats_start_at_zero);
    RUN_TEST(test_sctp_ngap_packet_is_categorized);
    RUN_TEST(test_http_packet_is_not_categorized);

    bpf_object__close(obj); /* also closes every fd this object owns (prog + all its maps) */

    return test_summary();
}
