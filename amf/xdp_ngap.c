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

/* Reported NGAP DATA chunks used to only go to bpf_printk() (visible via
 * `sudo cat /sys/kernel/debug/tracing/trace_pipe`); now they're submitted
 * here instead, for test/test_xdp.c to poll and print directly -- same
 * ringbuf + userspace ring_buffer__poll() pattern amf_tracer.bpf.c /
 * amf_loader.c already use, just this program's own private ringbuf and
 * record type (see xdp_ngap_event.h). HTTP/1.x requests and responses
 * share this same ringbuf, tagged via struct xdp_event's `type` field. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   /* 64 KB -- neither NGAP nor incidental HTTP traffic here is high-rate, no need for amf_tracer.bpf.c's 16 MB */
} events SEC(".maps");

static __always_inline void dump_bytes(void *base, void *data_end) {
    for (int i = 0; i < 32; i++) {
        if (base + i + 1 > data_end)
            break;

        __u8 b = *(__u8 *)(base + i);
        bpf_printk("ngap[%d]=0x%x", i, b);
    }
}

/* SCTP/NGAP: unchanged logic from before HTTP was added, just pulled out
 * into its own function so xdp_prog() can branch on iph->protocol
 * instead of returning early inline. Identifies NGAP the same way it
 * always did -- not by port, but by the SCTP DATA chunk's PPID (60 is
 * IANA-assigned to NGAP), the wire-level equivalent of the HTTP method
 * check handle_tcp() below does for its own protocol. */
static __always_inline int handle_sctp(struct iphdr *iph, void *data_end)
{
    /* ---- Get SCTP header and data chunk ---- */
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

    /* Report this NGAP DATA chunk to the loader instead of bpf_printk()
     * -- reserve a slot, fill it, submit. A NULL reserve (ringbuf full)
     * just means this one event is dropped; never worth failing the
     * packet over, so fall through to XDP_PASS either way. */
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

/* TCP/HTTP: same shallow, wire-only inspection depth as handle_sctp()
 * above -- no full HTTP parse, just enough to tell "this looks like an
 * HTTP/1.x request or response line" from the first few bytes of the TCP
 * payload. Deliberately NOT filtered by port (unlike a typical "port 80"
 * check): SCTP/NGAP above is identified by wire content (the DATA
 * chunk's PPID), not by port either, so this stays consistent with that
 * same content-based approach rather than assuming HTTP only ever runs
 * on one specific port. */
static __always_inline int handle_tcp(struct iphdr *iph, void *data_end)
{
    void *tcp_ptr = (void *)iph + (iph->ihl * 4);

    struct tcphdr *tcp = tcp_ptr;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // TCP header length may be > 20 bytes (options present)
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload + 4 > data_end)
        return XDP_PASS; /* no ACK-only/empty segment has enough bytes to be a request/status line */

    __u8 c0 = *(__u8 *)(payload + 0);
    __u8 c1 = *(__u8 *)(payload + 1);
    __u8 c2 = *(__u8 *)(payload + 2);
    __u8 c3 = *(__u8 *)(payload + 3);

    /* Match the first 3-4 bytes against common HTTP/1.x request methods
     * and the "HTTP/" response status-line prefix -- a fixed, bounded set
     * of literal comparisons (verifier-friendly; no scanning/loops over
     * unknown-length data), same trick used elsewhere in eBPF for cheap
     * L7 protocol sniffing. */
    char method[8] = {};

    if (c0=='G' && c1=='E' && c2=='T' && c3==' ')
        __builtin_memcpy(method, "GET", 4);
    else if (c0=='P' && c1=='O' && c2=='S' && c3=='T')
        __builtin_memcpy(method, "POST", 5);
    else if (c0=='P' && c1=='U' && c2=='T' && c3==' ')
        __builtin_memcpy(method, "PUT", 4);
    else if (c0=='H' && c1=='E' && c2=='A' && c3=='D')
        __builtin_memcpy(method, "HEAD", 5);
    else if (c0=='D' && c1=='E' && c2=='L' && c3=='E')
        __builtin_memcpy(method, "DELETE", 7);
    else if (c0=='P' && c1=='A' && c2=='T' && c3=='C')
        __builtin_memcpy(method, "PATCH", 6);
    else if (c0=='O' && c1=='P' && c2=='T' && c3=='I')
        __builtin_memcpy(method, "OPTIONS", 8);
    else if (c0=='H' && c1=='T' && c2=='T' && c3=='P')
        __builtin_memcpy(method, "HTTP", 5); /* response status line, e.g. "HTTP/1.1 200 OK" */
    else
        return XDP_PASS; /* not a recognizable HTTP/1.x line -- ordinary TCP traffic, ignore */

    struct xdp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->type  = XDP_EVT_HTTP;
        e->saddr = iph->saddr;
        e->daddr = iph->daddr;
        e->sport = bpf_ntohs(tcp->source);
        e->dport = bpf_ntohs(tcp->dest);
        __builtin_memcpy(e->method, method, sizeof(e->method));
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

    // Only SCTP/NGAP and TCP/HTTP are of interest; everything else
    // (UDP, ICMP, ...) passes through untouched.
    if (iph->protocol == IPPROTO_SCTP)
        return handle_sctp(iph, data_end);

    if (iph->protocol == IPPROTO_TCP)
        return handle_tcp(iph, data_end);

    return XDP_PASS;
}