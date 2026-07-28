#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_ngap_event.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_SCTP 132
#define SCTP_PPID_NGAP 60
#define SCTP_DATA 0

struct sctphdr_simple {
    __u16 source;
    __u16 dest;
    __u32 vtag;
    __u32 checksum;
};

struct sctp_data_chunk {
    __u8 type;
    __u8 flags;
    __u16 length;
    __u32 tsn;
    __u16 stream_id;
    __u16 stream_seq;
    __u32 ppid;
};

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for reporting XDP events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Printing detail
static __always_inline void dump_bytes(void *base, void *data_end) {
    for (int i = 0; i < 32; i++) {
        if (base + i + 1 > data_end)
            break;

        __u8 b = *(__u8 *)(base + i);
        bpf_printk("ngap[%d]=0x%x", i, b);
    }
}

//  Get SCTP header and data chunk
static __always_inline int handle_sctp(struct iphdr *iph, void *data_end)
{
    // IP header length may be > 20 bytes
    void *sctp_ptr = (void *)iph + (iph->ihl * 4);

    // Check SCTP header size
    struct sctphdr_simple *sctp = sctp_ptr;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    // Check SCTP data chunk size
    struct sctp_data_chunk *chunk = (void *)(sctp + 1);
    if ((void *)(chunk + 1) > data_end)
        return XDP_PASS;

    /* Get chunk type, length, and PPID */
    __u8 chunk_type = chunk->type;
    __u16 chunk_len = bpf_ntohs(chunk->length);
    __u32 ppid = bpf_ntohl(chunk->ppid);

    if (chunk_type != SCTP_DATA)
        return XDP_PASS;

    if (ppid != SCTP_PPID_NGAP)
        return XDP_PASS;

    // Dump the first 32 bytes of the NGAP message
    void *ngap = (void *)(chunk + 1);
    if (ngap + 16 > data_end)
        return XDP_PASS;
    __u8 b0 = *(__u8 *)(ngap + 0);
    __u8 b1 = *(__u8 *)(ngap + 1);
    __u8 b2 = *(__u8 *)(ngap + 2);

    __u16 procedure_code = ((__u16)b0 << 8) | b1;
    __u8 criticality = b2;

    /* Report this NGAP DATA chunk to the loader */
    struct xdp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        /* Zero everything EXCEPT raw[] (the last, large field) -- clang
         * can't inline a memset() over the whole struct now that raw[]
         * is MTU-sized (see handle_other()'s comment); this event type
         * never touches raw[]/raw_len anyway, and the loader only reads
         * those fields when e->type == XDP_EVT_OTHER, so leaving raw[]
         * un-zeroed here is harmless, not just a workaround. */
        __builtin_memset(e, 0, __builtin_offsetof(struct xdp_event, raw));
        e->type           = XDP_EVT_NGAP;
        e->saddr          = iph->saddr;
        e->daddr          = iph->daddr;
        e->sport          = bpf_ntohs(sctp->source);
        e->dport          = bpf_ntohs(sctp->dest);
        e->chunk_len      = chunk_len;
        e->procedure_code = procedure_code;
        e->criticality    = criticality;
        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}

// Get TCP header and TLS record (HTTPS is TLS -- there is no plaintext
// HTTP request line to match here, so identification happens at the TLS
// record layer instead, the same "read a few fixed wire bytes, no deep
// parse" depth handle_sctp() uses for NGAP).
static __always_inline int handle_tls(struct iphdr *iph, void *data_end)
{
    void *tcp_ptr = (void *)iph + (iph->ihl * 4);

    struct tcphdr *tcp = tcp_ptr;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // TCP header length may be > 20 bytes (options present)
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload + 5 > data_end)
        return XDP_PASS; /* not enough bytes for a TLS record header (type[1] + version[2] + length[2]) */

    __u8 content_type = *(__u8 *)(payload + 0);
    __u8 ver_major     = *(__u8 *)(payload + 1);

    /* TLS record layer: ContentType 0x16 (Handshake -- ClientHello,
     * ServerHello, Certificate, ...) or 0x17 (Application Data -- the
     * actual encrypted HTTPS payload after the handshake completes),
     * with a TLS-range major version. Every TLS version, including 1.3,
     * advertises major=3 at the record layer (TLS 1.3's real version
     * lives in an extension instead, for middlebox compatibility), so
     * checking major==3 alone covers SSLv3 through TLS 1.3 without
     * needing to special-case any of them. Not filtered by port 443 --
     * same content-based-not-port-based approach handle_sctp() uses for
     * NGAP via the SCTP DATA chunk's PPID. */
    if (ver_major != 0x03)
        return XDP_PASS;

    char tls_record[8] = {};
    switch (content_type) {
    case 0x16: __builtin_memcpy(tls_record, "TLS-HS", 7); break; /* Handshake */
    case 0x17: __builtin_memcpy(tls_record, "TLS-AD", 7); break; /* Application Data */
    default:   return XDP_PASS; /* not a TLS record we care about (e.g. 0x14 change_cipher_spec, 0x15 alert) */
    }

    struct xdp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        /* See handle_sctp()'s comment -- same offsetof() trick, same
         * reason (raw[]/raw_len are never read for this event type). */
        __builtin_memset(e, 0, __builtin_offsetof(struct xdp_event, raw));
        e->type  = XDP_EVT_HTTPS;
        e->saddr = iph->saddr;
        e->daddr = iph->daddr;
        e->sport = bpf_ntohs(tcp->source);
        e->dport = bpf_ntohs(tcp->dest);
        __builtin_memcpy(e->tls_record, tls_record, sizeof(e->tls_record));
        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}

// DIAGNOSTIC: catch-all for anything that isn't SCTP. No protocol-
// specific parsing -- reports source/destination IP plus a raw byte dump
// of EVERY such packet, starting at the IP header itself (confirmed via
// the earlier pkt_addr/iph_addr capture to sit right at pkt+14, i.e.
// pkt+sizeof(struct ethhdr), same as any standard untagged Ethernet
// frame), for the loader to print as a hex+ASCII dump.
//
// Copies via bpf_xdp_load_bytes() (kernel >= 5.18) instead of a manually
// unrolled per-byte loop: that loop's own instruction count scaled
// directly with XDP_EVT_OTHER_RAW_MAX, which became a real verifier-
// complexity risk once that constant grew toward MTU size (1480) to stop
// truncating real payloads. bpf_xdp_load_bytes() does the equivalent
// bounded copy as a single helper call regardless of length -- and,
// unlike raw pointer dereference against ctx->data/data_end, also
// correctly follows multi-buffer ("xdp_frags") packets whose data spans
// more than one buffer, not just whatever's in the first one.
static __always_inline int handle_other(struct xdp_md *ctx, struct iphdr *iph, void *data, void *data_end)
{
    struct xdp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        /* Zero everything EXCEPT raw[] itself -- clang-for-BPF can't
         * inline a memset() over the whole struct now that raw[] is
         * MTU-sized (1480 bytes); it falls back to an actual memset()
         * call, which doesn't exist in a BPF program ("A call to
         * built-in function 'memset' is not supported"). Not a problem
         * here: raw[] gets overwritten by bpf_xdp_load_bytes() below up
         * to `want` bytes, and the loader never reads past raw_len, so
         * whatever's left in raw[want..] (stale ringbuf memory from a
         * prior reservation) is simply never seen. */
        __builtin_memset(e, 0, __builtin_offsetof(struct xdp_event, raw));
        e->type  = XDP_EVT_OTHER;
        e->saddr = iph->saddr;
        e->daddr = iph->daddr;

        /* offset is iph's distance from the frame's own start (normally
         * 14, i.e. sizeof(struct ethhdr), but computed rather than
         * assumed -- same reasoning as the pkt_addr/iph_addr capture
         * that first confirmed it). avail clamps the request to however
         * many bytes actually remain in THIS packet, capped at
         * XDP_EVT_OTHER_RAW_MAX -- both bounds bpf_xdp_load_bytes()
         * itself needs the length argument to respect. */
        __u32 offset = (__u32)((__u8 *)iph - (__u8 *)data);
        __u32 avail  = (__u32)((__u8 *)data_end - (__u8 *)iph);
        __u32 want   = avail < XDP_EVT_OTHER_RAW_MAX ? avail : XDP_EVT_OTHER_RAW_MAX;

        /* avail is always >= sizeof(struct iphdr) in practice -- xdp_prog()
         * already checked (void *)(iph + 1) <= data_end before iph was
         * ever handed to this function -- but the verifier loses that
         * tight bound across the pointer-subtraction + truncating
         * (__u32) cast above, leaving `want`'s provable range at
         * [0, XDP_EVT_OTHER_RAW_MAX]. bpf_xdp_load_bytes()'s length
         * argument doesn't tolerate a possibly-zero value ("invalid
         * zero-sized read"), so this explicit branch exists purely to
         * give the verifier a fact to narrow on: on the path that
         * reaches the call below, it can now prove want > 0. */
        if (want > 0) {
            if (bpf_xdp_load_bytes(ctx, offset, e->raw, want) == 0)
                e->raw_len = (__u16)want;
            /* else: leave raw_len at 0 (already zeroed above) -- still
             * worth submitting the event for its saddr/daddr alone. */
        }

        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check ethernet header size
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the packet is IPv4
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

    if (iph->protocol == IPPROTO_SCTP)
        return handle_sctp(iph, data_end);

    // DIAGNOSTIC: treat every other non-SCTP packet as "TCP" for this
    // test and report its src/dest IP + raw bytes via handle_other() --
    // bypasses handle_tls()'s TLS-record matching entirely so every
    // non-SCTP packet prints, not just the ones that look like TLS.
    return handle_other(ctx, iph, data, data_end);
}
