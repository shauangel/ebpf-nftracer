#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

    // Find SCTP packets
    // if (iph->protocol == IPPROTO_SCTP)
    // {
    //     bpf_printk("XDP eth proto=0x%x IP proto=%d src=%x dst=%x\n",
    //                bpf_ntohs(eth->h_proto),
    //                iph->protocol,
    //                iph->saddr,
    //                iph->daddr);
    // }

    if (iph->protocol != IPPROTO_SCTP)
        return XDP_PASS;

    // IP header length may be > 20 bytes
    void *sctp_ptr = (void *)iph + (iph->ihl * 4);

    struct sctphdr_simple *sctp = sctp_ptr;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    struct sctp_data_chunk *chunk = (void *)(sctp + 1);
    if ((void *)(chunk + 1) > data_end)
        return XDP_PASS;

    __u8 chunk_type = chunk->type;
    __u16 chunk_len = bpf_ntohs(chunk->length);
    __u32 ppid = bpf_ntohl(chunk->ppid);

    if (chunk_type != SCTP_DATA)
        return XDP_PASS;

    if (ppid != SCTP_PPID_NGAP)
        return XDP_PASS;

    void *ngap = (void *)(chunk + 1);
    if (ngap + 16 > data_end)
        return XDP_PASS;
    __u8 b0 = *(__u8 *)(ngap + 0);
    __u8 b1 = *(__u8 *)(ngap + 1);
    __u8 b2 = *(__u8 *)(ngap + 2);

    __u16 procedure_code = ((__u16)b0 << 8) | b1;
    __u8 criticality = b2;


    bpf_printk("--> SCTP sport=%d dport=%d chunk=%d len=%d ppid=%d",
            bpf_ntohs(sctp->source),
            bpf_ntohs(sctp->dest),
            chunk_type,
            chunk_len,
            ppid);

    bpf_printk("NGAP procedureCode=%d criticality=0x%x <--",
            procedure_code, criticality);

    return XDP_PASS;
}