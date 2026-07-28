/* Must come before any #include: glibc hides POSIX/BSD extensions this
 * file needs -- localtime_r() (POSIX.1-2001), strtok_r() (POSIX.1-2001)
 * -- when compiled with a strict -std=c11 (see this directory's
 * Makefile), unless a feature-test macro says otherwise. _GNU_SOURCE is
 * the blanket "expose everything glibc has" macro; only matters on glibc
 * (Darwin/macOS libc doesn't gate these the same way, which is why this
 * didn't show up until built on the real Linux target). */
#define _GNU_SOURCE

/*
 * test_xdp.c — auto-attaching loader + detach watchdog for ../xdp_ngap.c.
 *
 * ../xdp_ngap.c is the passive, legacy XDP program (single SEC("xdp")
 * program "xdp_prog", no maps of its own -- see ../README.md's
 * "xdp_ngap.c (legacy, superseded)" section): it parses Ethernet/IP/SCTP/
 * NGAP and bpf_printk()s the procedure code, always returning XDP_PASS.
 * ../README.md documents attaching it by hand:
 *
 *   clang -O2 -g -target bpf ... -c amf_xdp.c -o amf_xdp.o
 *   sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
 *
 * This file does that same load+attach from C instead of a shell one-liner,
 * against the exact same target interface, and then keeps running as a
 * watchdog:
 *
 *   1. attaches automatically -- waits for veth5538fab to exist rather
 *      than requiring it to already be up, and picks native (driver) XDP
 *      mode first, falling back to generic (SKB) mode if the interface
 *      doesn't support native XDP.
 *   2. alerts if the program is ever no longer the one attached to that
 *      interface -- whether because someone ran `ip link set dev
 *      veth5538fab xdp off`, a different program replaced it, or the
 *      interface itself was torn down and possibly recreated. Detected by
 *      polling bpf_xdp_query_id() every POLL_INTERVAL_SEC seconds and
 *      comparing against the id this process itself attached -- there is
 *      no netlink "XDP program removed" event to subscribe to instead, so
 *      polling is the standard way real XDP loaders (e.g. xdp-loader)
 *      handle this too.
 *
 * Requires Linux, libbpf with bpf_xdp_attach()/bpf_xdp_detach()/
 * bpf_xdp_query_id() (libbpf >= 0.6), and root (CAP_BPF + CAP_NET_ADMIN --
 * attaching an XDP program needs real network privileges on top of the
 * CAP_BPF the rest of this test suite already requires).
 */

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>        /* inet_ntop(), inet_pton(), INET_ADDRSTRLEN */
#include <net/if.h>          /* if_nametoindex() */
#include <netinet/in.h>      /* struct in_addr -- NF name resolution via `docker inspect` */
#include <linux/if_link.h>   /* XDP_FLAGS_* attach-mode flags */

#include <bpf/libbpf.h>      /* bpf_object__open_file/__load, bpf_program__fd, ring_buffer__* */
#include <bpf/bpf.h>         /* bpf_xdp_attach/detach/query_id, bpf_obj_get_info_by_fd */

#include "../xdp_ngap_event.h" /* struct xdp_event -- shared with ../xdp_ngap.c's "events" ringbuf */

/* Default attach target -- the host-side veth of the AMF container's N2
 * interface, same as ../amf_xdp.c's documented attach point. Overridable
 * as argv[1] for testing against some other interface without editing
 * this file. */
#define DEFAULT_IFACE "veth5538fab"

/* Built by this directory's Makefile (see the xdp_ngap.bpf.o rule) from
 * ../xdp_ngap.c -- kept in amf/test/, nothing added to amf/ itself. */
#define XDP_OBJ_PATH   "xdp_ngap.bpf.o"
#define XDP_PROG_NAME  "xdp_prog" /* matches SEC("xdp") int xdp_prog(...) in xdp_ngap.c */
#define XDP_EVENTS_MAP "events"   /* matches the BPF_MAP_TYPE_RINGBUF SEC(".maps") in xdp_ngap.c */

#define POLL_INTERVAL_SEC 2

/* ── Ctrl+C / SIGTERM handling -- same pattern ../amf_loader.c uses ────── */
static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { (void)sig; stop = 1; }

/* Wall-clock "HH:MM:SS" prefix for log lines (distinct from
 * ../amf_loader.c's fmt_ts(), which formats a boot-relative
 * bpf_ktime_get_ns() timestamp -- there's no BPF ring-buffer event here,
 * just this process's own clock). */
static void print_ts(FILE *f)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(f, "[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

#define ALERT(...) \
    do { \
        print_ts(stderr); \
        fprintf(stderr, "*** ALERT: " __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } while (0)

#define LOG(...) \
    do { \
        print_ts(stdout); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } while (0)

/* ── NF name resolution for XDP_EVT_OTHER's src/dst -------------------
 * This environment has no docker-compose/free5gc config checked into
 * this repo to hardcode an IP->NF table from, and these are docker
 * compose service containers, not host-level hostnames -- so instead of
 * a host DNS/getnameinfo() reverse lookup (which a process running on
 * the HOST can't resolve anyway; Docker's embedded DNS that knows
 * container names is only reachable from inside a container on that
 * network), this asks Docker directly: `docker inspect` on every running
 * container reports each one's name and every IP it holds on every
 * network it's attached to. Built ONCE (lazily, on the first lookup)
 * into addr_cache[] below rather than re-invoking `docker` per packet --
 * this runs inside handle_xdp_event(), itself inside
 * ring_buffer__poll(), so spawning a process per lookup would directly
 * stall this loader's detach-watchdog tick.
 *
 * Falls back to the plain IP for anything not found (a non-container
 * address, a container started after the cache was built, or `docker`
 * not being installed/reachable at all) -- no behavior lost either way. */
#define ADDR_CACHE_MAX 64
static struct {
    __u32 addr; /* network byte order, same as struct xdp_event's saddr/daddr */
    char  name[80];
} addr_cache[ADDR_CACHE_MAX];
static int  addr_cache_count = 0;
static bool addr_cache_built = false;

/* Runs once: `docker inspect --format '{{.Name}} {{IP}} {{IP}} ...'` on
 * every running container, one line per container, and caches an entry
 * per (container, IP) pair -- a container can hold more than one IP if
 * it's attached to more than one compose network. `docker ps -q`
 * expanding to nothing (no containers, or `docker` missing entirely)
 * just means the inspect line has no arguments and fails harmlessly;
 * either way popen()'s stdout ends up empty and the cache stays empty,
 * so every address falls back to its plain IP -- same as if this
 * function were never called. */
static void build_addr_cache(void)
{
    FILE *fp = popen(
        "docker inspect --format "
        "'{{.Name}} {{range $net, $cfg := .NetworkSettings.Networks}}{{$cfg.IPAddress}} {{end}}' "
        "$(docker ps -q 2>/dev/null) 2>/dev/null", "r");
    if (!fp)
        return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *saveptr = NULL;
        char *tok = strtok_r(line, " \t\n", &saveptr);
        if (!tok)
            continue;
        const char *name = (tok[0] == '/') ? tok + 1 : tok; /* docker inspect prefixes names with '/' */

        while ((tok = strtok_r(NULL, " \t\n", &saveptr)) != NULL) {
            if (addr_cache_count >= ADDR_CACHE_MAX)
                break;
            struct in_addr ip;
            if (inet_pton(AF_INET, tok, &ip) != 1)
                continue; /* not a valid IPv4 address (e.g. an unattached network's empty entry) */

            addr_cache[addr_cache_count].addr = ip.s_addr;
            snprintf(addr_cache[addr_cache_count].name, sizeof(addr_cache[addr_cache_count].name),
                     "%s(%s)", name, tok);
            addr_cache_count++;
        }
    }
    pclose(fp);
}

static void resolve_addr(__u32 addr_be, char *out, size_t out_sz)
{
    if (!addr_cache_built) {
        build_addr_cache();
        addr_cache_built = true;
    }

    for (int i = 0; i < addr_cache_count; i++) {
        if (addr_cache[i].addr == addr_be) {
            snprintf(out, out_sz, "%s", addr_cache[i].name);
            return;
        }
    }

    inet_ntop(AF_INET, &addr_be, out, out_sz);
}

/* ── lightweight IP/TCP header decoder for XDP_EVT_OTHER's raw[] dump ───
 * Pure userspace, parses the same bytes the hex dump already shows --
 * no BPF-side changes needed. Only decodes what's needed to tell a real
 * header apart from noise: IP version/IHL/total_len/ttl/proto, and (for
 * TCP) ports/seq/ack/flags/window. No options beyond that, no payload
 * parsing -- "lightweight" on purpose, not a full protocol stack. */

static const char *ip_proto_name(__u8 proto)
{
    switch (proto) {
    case 1:   return "ICMP";
    case 6:   return "TCP";
    case 17:  return "UDP";
    case 132: return "SCTP";
    default:  return "?";
    }
}

/* TCP flags byte -> "SYN,ACK" style string. Order matches how they're
 * conventionally listed (tcpdump-style), not bit order. */
static void decode_tcp_flags(__u8 flags, char *out, size_t out_sz)
{
    static const struct { __u8 bit; const char *name; } known[] = {
        { 0x20, "URG" }, { 0x10, "ACK" }, { 0x08, "PSH" },
        { 0x04, "RST" }, { 0x02, "SYN" }, { 0x01, "FIN" },
    };
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (!(flags & known[i].bit))
            continue;
        if (out[0])
            strncat(out, ",", out_sz - strlen(out) - 1);
        strncat(out, known[i].name, out_sz - strlen(out) - 1);
    }
    if (!out[0])
        strncpy(out, "-", out_sz - 1);
}

/* Decoded fields, IP header first, then (if proto == TCP and enough
 * bytes were captured) the TCP header right after it. Populated by
 * decode_ip_tcp() below with NO printing -- callers get to decide
 * whether anything here is worth displaying (namely: whether there's a
 * payload) before printing a single character. */
struct ip_tcp_info {
    __u8  version, ihl, ttl, proto;
    __u16 total_len;

    int   has_tcp;         /* 1 if proto == TCP and its header was fully captured */
    __u16 sport, dport;
    __u32 seq, ack;
    __u8  doff;             /* TCP data offset, in bytes (already *4'd) */
    __u8  flags;
    __u16 window;

    __u16 hdrs_len;         /* ihl + doff -- only meaningful if has_tcp */
    __u16 payload_len;      /* raw_len - hdrs_len, 0 if no TCP or nothing follows the headers */
};

/* Parses raw[0..raw_len) into *info. raw[] is a fixed-size capture (see
 * XDP_EVT_OTHER_RAW_MAX), so a packet with TCP options can easily have
 * its payload (or even the full TCP header) cut off -- info.has_tcp /
 * info.payload_len reflect exactly how far parsing actually got, rather
 * than guessing at missing bytes. Returns 0 only if raw_len is too short
 * for even a bare IP header (*info is still zeroed in that case). */
static int decode_ip_tcp(const __u8 *raw, __u16 raw_len, struct ip_tcp_info *info)
{
    memset(info, 0, sizeof(*info));
    if (raw_len < 20)
        return 0;

    info->version   = raw[0] >> 4;
    info->ihl       = (raw[0] & 0x0F) * 4; /* IHL is in 32-bit words */
    info->total_len = ((__u16)raw[2] << 8) | raw[3];
    info->ttl       = raw[8];
    info->proto     = raw[9];

    if (info->proto != 6 /* TCP */ || raw_len < (__u16)(info->ihl + 20))
        return 1; /* not TCP, or its header got cut off in this capture */

    const __u8 *tcp = raw + info->ihl;
    info->has_tcp = 1;
    info->sport   = ((__u16)tcp[0] << 8) | tcp[1];
    info->dport   = ((__u16)tcp[2] << 8) | tcp[3];
    info->seq     = ((__u32)tcp[4] << 24) | ((__u32)tcp[5] << 16) | ((__u32)tcp[6] << 8) | tcp[7];
    info->ack     = ((__u32)tcp[8] << 24) | ((__u32)tcp[9] << 16) | ((__u32)tcp[10] << 8) | tcp[11];
    info->doff    = (tcp[12] >> 4) * 4;
    info->flags   = tcp[13];
    info->window  = ((__u16)tcp[14] << 8) | tcp[15];

    info->hdrs_len = info->ihl + info->doff;
    if (raw_len > info->hdrs_len)
        info->payload_len = raw_len - info->hdrs_len;

    return 1;
}

static void print_ip_tcp_info(const struct ip_tcp_info *info)
{
    printf("    IP:  v=%u ihl=%u total_len=%u ttl=%u proto=%s(%u)\n",
           info->version, info->ihl, info->total_len, info->ttl,
           ip_proto_name(info->proto), info->proto);

    if (!info->has_tcp)
        return;

    char flag_str[32];
    decode_tcp_flags(info->flags, flag_str, sizeof(flag_str));
    printf("    TCP: sport=%u dport=%u seq=%u ack=%u flags=[%s] window=%u hdrlen=%u\n",
           info->sport, info->dport, info->seq, info->ack, flag_str, info->window, info->doff);
}

/* Hex+ASCII dump of just the payload bytes (raw[hdrs_len .. hdrs_len+
 * payload_len)), labeled separately from the full-packet dump so it
 * doesn't have to be found by hand-counting into it. Still just whatever
 * fits in this capture -- a large HTTP/2 frame or JSON body can run past
 * XDP_EVT_OTHER_RAW_MAX's end. Only ever called when payload_len > 0. */
static void print_payload_dump(const __u8 *raw, __u16 hdrs_len, __u16 payload_len)
{
    printf("    payload: %u byte(s) captured:\n", payload_len);
    for (__u16 off = 0; off < payload_len; off += 16) {
        char hex[16 * 3 + 1] = {0};
        char ascii[17] = {0};
        int n = (payload_len - off < 16) ? (payload_len - off) : 16;
        for (int i = 0; i < n; i++) {
            __u8 b = raw[hdrs_len + off + i];
            snprintf(hex + i * 3, 4, "%02x ", b);
            ascii[i] = isprint(b) ? (char)b : '.';
        }
        printf("      %04u: %-48s %s\n", (unsigned)off, hex, ascii);
    }
}

/* ring_buffer__new()'s callback -- fires once per struct xdp_event
 * xdp_prog() submits, whether that's a real NGAP DATA chunk or a TLS
 * (HTTPS) record (see xdp_ngap_event.h's XDP_EVT_*).
 * This is "the trace ... show[ing] in the loader": previously the only
 * way to see the NGAP side of this was `sudo cat /sys/kernel/debug/
 * tracing/trace_pipe` catching xdp_ngap.c's old bpf_printk() calls; now
 * both kinds print right here, in this process, as part of the same
 * watchdog output. Return value is libbpf's "keep polling" signal -- 0
 * always, same as ../amf_loader.c's handle_event(). */
static int handle_xdp_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct xdp_event))
        return 0; /* short record -- shouldn't happen for a fixed-size struct, ignore defensively */

    const struct xdp_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));

    switch (e->type) {
    case XDP_EVT_NGAP:
        LOG("NGAP  %s:%u -> %s:%u  len=%u  procedureCode=%u  criticality=%u",
            src, e->sport, dst, e->dport, e->chunk_len, e->procedure_code, e->criticality);
        break;
    case XDP_EVT_HTTPS:
        LOG("HTTPS %s:%u -> %s:%u  %s",
            src, e->sport, dst, e->dport, e->tls_record);
        break;
    case XDP_EVT_OTHER: {
        /* DIAGNOSTIC/TEMPORARY event -- see handle_other() in
         * ../xdp_ngap.c, fires for every non-SCTP packet with a raw byte
         * dump starting at the IP header (confirmed to sit right at
         * pkt+14 -- see the earlier pkt_addr/iph_addr capture this
         * replaced). Decoded first, silently: pure control segments
         * (no payload -- SYN/ACK/FIN with nothing behind the headers)
         * print NOTHING at all, since there's nothing worth looking at.
         * Only once payload_len > 0 do we print anything -- the
         * addresses, the decoded IP/TCP fields, the payload itself, and
         * the full raw hex+ASCII dump underneath as ground truth in case
         * the decoder missed something (fragmented/malformed header,
         * non-TCP traffic, etc). */
        struct ip_tcp_info info;
        decode_ip_tcp(e->raw, e->raw_len, &info);
        if (info.payload_len == 0)
            break;

        char src_name[80], dst_name[80];
        resolve_addr(e->saddr, src_name, sizeof(src_name));
        resolve_addr(e->daddr, dst_name, sizeof(dst_name));

        LOG("TCP %s -> %s  (%u raw bytes captured, IP header onward)",
            src_name, dst_name, e->raw_len);
        print_ip_tcp_info(&info);
        print_payload_dump(e->raw, info.hdrs_len, info.payload_len);

        for (__u16 off = 0; off < e->raw_len; off += 16) {
            char hex[16 * 3 + 1] = {0};
            char ascii[17] = {0};
            int n = (e->raw_len - off < 16) ? (e->raw_len - off) : 16;
            for (int i = 0; i < n; i++) {
                snprintf(hex + i * 3, 4, "%02x ", e->raw[off + i]);
                ascii[i] = isprint(e->raw[off + i]) ? (char)e->raw[off + i] : '.';
            }
            printf("    %04u: %-48s %s\n", (unsigned)off, hex, ascii);
        }
        break;
    }
    default:
        LOG("xdp_event: unknown type=%u from %s:%u -> %s:%u", e->type, src, e->sport, dst, e->dport);
        break;
    }
    return 0;
}

/* Blocks (polling once a second) until `ifname` exists, returning its
 * ifindex -- or -1 if a signal set `stop` while waiting. This is what
 * makes attaching "automatic": the caller doesn't need the interface to
 * already be up (e.g. the AMF container hasn't started yet), just
 * eventually present. */
static int wait_for_ifindex(const char *ifname)
{
    bool printed = false;
    while (!stop) {
        unsigned idx = if_nametoindex(ifname);
        if (idx != 0)
            return (int)idx;
        if (!printed) {
            LOG("waiting for interface \"%s\" to appear...", ifname);
            printed = true;
        }
        sleep(1);
    }
    return -1;
}

/* Attaches prog_fd to ifindex, trying native (driver) XDP mode first and
 * falling back to generic (SKB) mode -- native mode isn't supported on
 * every interface/driver, but generic mode works everywhere, including a
 * veth pair, at some per-packet cost. XDP_FLAGS_UPDATE_IF_NOEXIST makes
 * both attempts fail (instead of silently replacing) if some OTHER
 * program is already attached, so this loader can never accidentally
 * steal a program a real session already has running on the interface.
 * On success, *flags_used records which mode won, needed later to detach
 * with matching flags. Returns 0 on success, -1 (errno set from the last
 * attempt) if neither mode worked. */
static int attach_xdp(int ifindex, int prog_fd, __u32 *flags_used)
{
    static const __u32 modes[] = {
        XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
    };
    static const char *mode_names[] = { "native/driver", "generic/SKB" };

    int err = 0;
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        err = bpf_xdp_attach(ifindex, prog_fd, modes[i], NULL);
        if (err == 0) {
            *flags_used = modes[i];
            LOG("attached xdp_prog to ifindex %d in %s mode", ifindex, mode_names[i]);
            return 0;
        }
    }
    if (err == -EBUSY || errno == EBUSY)
        fprintf(stderr,
                "attach_xdp: ifindex %d already has an XDP program attached "
                "(EBUSY) -- run `sudo ip link set dev <iface> xdp off` first "
                "if that's a stale program from a previous, uncleanly-stopped "
                "run of this loader.\n", ifindex);
    return -1;
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr,
                "%s: must run as root -- attaching an XDP program needs "
                "CAP_BPF + CAP_NET_ADMIN.\nTry: sudo ./%s\n",
                argc > 0 ? argv[0] : "test_xdp", argc > 0 ? argv[0] : "test_xdp");
        return 1;
    }

    const char *ifname = (argc > 1) ? argv[1] : DEFAULT_IFACE;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    LOG("test_xdp: loading %s (prog \"%s\") for interface \"%s\"",
        XDP_OBJ_PATH, XDP_PROG_NAME, ifname);

    /* Requirement 1: attach automatically -- don't require the interface
     * to already exist at startup. */
    int ifindex = wait_for_ifindex(ifname);
    if (ifindex < 0)
        return 0; /* Ctrl+C while still waiting -- nothing was attached, nothing to clean up */

    struct bpf_object *obj = bpf_object__open_file(XDP_OBJ_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "test_xdp: bpf_object__open_file(%s): %s\n",
                XDP_OBJ_PATH, strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "test_xdp: bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, XDP_PROG_NAME);
    if (!prog) {
        fprintf(stderr, "test_xdp: program \"%s\" not found in %s\n",
                XDP_PROG_NAME, XDP_OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    /* Find the "events" ringbuf and start draining it -- this is what
     * makes xdp_prog's NGAP reports show up here instead of only via
     * trace_pipe. Done before attaching so no event submitted the moment
     * attach_xdp() succeeds can be missed. */
    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, XDP_EVENTS_MAP);
    if (!events_map) {
        fprintf(stderr, "test_xdp: map \"%s\" not found in %s\n", XDP_EVENTS_MAP, XDP_OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(events_map), handle_xdp_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "test_xdp: ring_buffer__new: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    __u32 xdp_flags = 0;
    if (attach_xdp(ifindex, prog_fd, &xdp_flags) != 0) {
        fprintf(stderr, "test_xdp: attach_xdp: %s\n", strerror(errno));
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 1;
    }

    /* Record OUR program's kernel id -- what the watchdog loop below
     * compares against every poll to notice a detach/replace. */
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
        fprintf(stderr, "test_xdp: bpf_obj_get_info_by_fd: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, xdp_flags, NULL);
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 1;
    }
    __u32 our_prog_id = info.id;
    LOG("attached: ifindex=%d prog_id=%u -- watching for detachment (Ctrl+C to stop)",
        ifindex, our_prog_id);

    /* Requirement 2: alert on detachment, in any of its forms. Tracked as
     * a small state machine so an alert only prints once per state
     * CHANGE (not once per poll) and a "recovered" line prints when
     * things go back to normal -- avoids a flood of identical alerts
     * every POLL_INTERVAL_SEC while the underlying problem persists. */
    enum { STATE_ATTACHED, STATE_DETACHED, STATE_REPLACED, STATE_IFACE_GONE } state = STATE_ATTACHED;

    while (!stop) {
        /* Doubles as the watchdog's tick AND the event drain: blocks up
         * to POLL_INTERVAL_SEC, waking early to invoke handle_xdp_event()
         * as soon as xdp_prog() submits one, so NGAP/HTTPS reports show up
         * with real latency instead of only once per tick. A negative
         * return other than -EINTR (this process's own SIGINT/SIGTERM
         * handler interrupting the wait) is a real libbpf
         * error -- worth an alert, but not worth aborting the watchdog
         * loop over. */
        int n = ring_buffer__poll(rb, POLL_INTERVAL_SEC * 1000);
        if (stop)
            break;
        if (n < 0 && n != -EINTR)
            ALERT("ring_buffer__poll on \"%s\" events: %d", XDP_EVENTS_MAP, n);

        unsigned cur_ifindex = if_nametoindex(ifname);
        if (cur_ifindex == 0) {
            /* Case: the interface itself vanished (container/veth torn
             * down) -- the XDP program went with it. */
            if (state != STATE_IFACE_GONE) {
                ALERT("interface \"%s\" disappeared -- xdp_prog is no longer attached anywhere", ifname);
                state = STATE_IFACE_GONE;
            }
            int new_idx = wait_for_ifindex(ifname); /* blocks until it comes back, or Ctrl+C */
            if (stop)
                break;
            ifindex = new_idx;
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("interface \"%s\" reappeared (ifindex=%d) -- re-attached automatically", ifname, ifindex);
                state = STATE_ATTACHED;
            } else {
                ALERT("interface \"%s\" reappeared but re-attach FAILED: %s", ifname, strerror(errno));
            }
            continue;
        }

        if ((int)cur_ifindex != ifindex) {
            /* Same name, different ifindex -- the old interface was
             * deleted and a new one created between polls without us
             * ever observing cur_ifindex==0 in between. Still means our
             * attachment (which was keyed to the OLD ifindex) is gone. */
            ALERT("interface \"%s\" was recreated (ifindex %d -> %d) -- re-attaching", ifname, ifindex, (int)cur_ifindex);
            ifindex = (int)cur_ifindex;
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("re-attached to new ifindex %d", ifindex);
                state = STATE_ATTACHED;
            } else {
                ALERT("re-attach after interface recreation FAILED: %s", strerror(errno));
                state = STATE_DETACHED;
            }
            continue;
        }

        __u32 cur_prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &cur_prog_id) != 0) {
            ALERT("failed to query XDP status on \"%s\": %s", ifname, strerror(errno));
            continue;
        }

        if (cur_prog_id == 0) {
            /* Case: someone ran `ip link set dev <iface> xdp off`, or
             * equivalent -- no XDP program attached at all anymore. */
            if (state != STATE_DETACHED) {
                ALERT("xdp_prog was DETACHED from \"%s\" (no XDP program attached)", ifname);
                state = STATE_DETACHED;
            }
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("re-attached automatically after detach");
                state = STATE_ATTACHED;
            }
        } else if (cur_prog_id != our_prog_id) {
            /* Case: a DIFFERENT XDP program is now attached -- e.g.
             * someone loaded amf_xdp.o (or anything else) over top of
             * ours. Deliberately does NOT fight to reclaim the interface
             * -- silently overriding another program back would be just
             * as surprising as the replacement itself. */
            if (state != STATE_REPLACED) {
                ALERT("xdp_prog on \"%s\" was REPLACED (expected prog_id=%u, found prog_id=%u)",
                      ifname, our_prog_id, cur_prog_id);
                state = STATE_REPLACED;
            }
        } else if (state != STATE_ATTACHED) {
            /* Recovered on its own (e.g. someone re-ran the exact same
             * ip link command pointing back at our program id). */
            LOG("xdp_prog is attached to \"%s\" again (prog_id=%u)", ifname, our_prog_id);
            state = STATE_ATTACHED;
        }
        /* state == STATE_ATTACHED and nothing changed: stay silent, per
         * this suite's convention of only printing on state changes. */
    }

    LOG("shutting down (Ctrl+C) -- detaching xdp_prog from \"%s\"", ifname);
    if (state == STATE_ATTACHED || state == STATE_REPLACED) {
        /* Only detach if we still believe OUR program (or at least
         * something) is at this ifindex; if the interface is gone there's
         * nothing left to detach. STATE_REPLACED: attempt it anyway --
         * bpf_xdp_detach() with our flags is a no-op / harmless error if
         * we don't actually own what's attached now. */
        if (bpf_xdp_detach(ifindex, xdp_flags, NULL) != 0)
            fprintf(stderr, "test_xdp: bpf_xdp_detach: %s (may already be detached)\n", strerror(errno));
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
