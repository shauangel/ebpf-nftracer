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

// TEMPORARY: one-entry latch so handle_other() below captures/dumps only
// the very first non-SCTP packet it sees, instead of one per packet.
// Remove this map along with the capture code in handle_other() once the
// manual inspection it's for is done.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} other_captured SEC(".maps");

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
        __builtin_memset(e, 0, sizeof(*e));
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
        __builtin_memset(e, 0, sizeof(*e));
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

// DIAGNOSTIC / TEMPORARY: catch-all for anything that isn't SCTP. No
// protocol-specific parsing -- just report source/destination IP, plus
// (once only, via other_captured's latch) a raw byte dump of the very
// first such packet, starting at the IP header itself, for manual
// inspection. Remove the capture block below (and other_captured above)
// once you've identified what's actually showing up here.
static __always_inline int handle_other(struct iphdr *iph, void *data_end)
{
    __u32 key = 0;
    __u8 already = 0;
    __u8 *captured = bpf_map_lookup_elem(&other_captured, &key);
    if (captured)
        already = *captured;

    struct xdp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->type  = XDP_EVT_OTHER;
        e->saddr = iph->saddr;
        e->daddr = iph->daddr;

        if (!already) {
            /* First non-SCTP packet seen -- dump raw bytes starting at
             * the IP header itself (covers the IP header's own fields
             * -- TTL, flags, options, ... -- plus whatever L4 protocol
             * follows, in one capture). Same bounded, unrolled-loop
             * pattern dump_bytes() above already uses, so it stays
             * verifier-friendly. */
            __u8 *src = (__u8 *)iph;
            __u16 n = 0;
            #pragma unroll
            for (int i = 0; i < XDP_EVT_OTHER_RAW_MAX; i++) {
                if ((void *)(src + i + 1) > data_end)
                    break;
                e->raw[i] = src[i];
                n = i + 1;
            }
            e->raw_len = n;

            __u8 one = 1;
            bpf_map_update_elem(&other_captured, &key, &one, BPF_ANY);
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
    // test and just report its src/dest IP via handle_other() -- bypasses
    // handle_tls()'s TLS-record matching (and any protocol.== IPPROTO_TCP
    // check) entirely, to isolate whether the problem is "no non-SCTP
    // traffic is reaching this program at all" vs. "the TLS-record match
    // itself is too narrow."
    return handle_other(iph, data_end);
}
