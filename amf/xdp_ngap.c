#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_ngap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_SCTP)
        return XDP_PASS;

    struct sctphdr *sctp = (void *)ip + ip->ihl * 4;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(sctp->dest) == 38412) {
        bpf_printk("AMF NGAP SCTP packet dst=38412\n");
    }

    return XDP_PASS;
}