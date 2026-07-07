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

    bpf_printk("XDP ifindex=%d eth proto=0x%x IP proto=%d",
               ctx->ingress_ifindex,
               bpf_ntohs(eth->h_proto),
               iph->protocol);

    return XDP_PASS;
}