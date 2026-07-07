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

    if (iph->protocol == IPPROTO_SCTP)
    {
        bpf_printk("XDP eth proto=0x%x IP proto=%d src=%x dst=%x\n",
                   bpf_ntohs(eth->h_proto),
                   iph->protocol,
                   iph->saddr,
                   iph->daddr);
    }

    return XDP_PASS;
}