#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_ngap_event.h"

#define ETH_P_IP 0x0800
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
 * record type (see xdp_ngap_event.h). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   /* 64 KB -- NGAP InitialUEMessage rate is low, no need for amf_tracer.bpf.c's 16 MB */
} events SEC(".maps");

static __always_inline void dump_bytes(void *base, void *data_end) {
    for (int i = 0; i < 32; i++) {
        if (base + i + 1 > data_end)
            break;

        __u8 b = *(__u8 *)(base + i);
        bpf_printk("ngap[%d]=0x%x", i, b);
    }
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

    // Check if the packet is SCTP
    if (iph->protocol != IPPROTO_SCTP)
        return XDP_PASS;

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
    struct ngap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->saddr          = iph->saddr;
        e->daddr          = iph->daddr;
        e->sport          = bpf_ntohs(sctp->source);
        e->dport          = bpf_ntohs(sctp->dest);
        e->chunk_len      = chunk_len;
        e->procedure_code = procedure_code;
        e->criticality    = criticality;
        __builtin_memset(e->_pad, 0, sizeof(e->_pad));
        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}