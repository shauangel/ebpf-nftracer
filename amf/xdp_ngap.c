#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif


char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_ngap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    // if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // bpf_printk("XDP eth proto=0x%x\n", bpf_ntohs(eth->h_proto));

    // if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // if ((void *)(ip + 1) > data_end) return XDP_PASS;

    bpf_printk("XDP eth proto=0x%x IP proto=%d src=%x dst=%x\n", bpf_ntohs(eth->h_proto), ip->protocol, ip->saddr, ip->daddr);

    if (ip->protocol != IPPROTO_SCTP) return XDP_PASS;

    __u32 ihl = ip->ihl * 4;
    if (ihl < 20) return XDP_PASS;

    struct sctphdr *sctp = (void *)ip + ihl;
    if ((void *)(sctp + 1) > data_end) return XDP_PASS;

    bpf_printk("SCTP sport=%d dport=%d\n",
               bpf_ntohs(sctp->source),
               bpf_ntohs(sctp->dest));


    return XDP_PASS;
}