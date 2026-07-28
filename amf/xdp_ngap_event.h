#ifndef XDP_NGAP_EVENT_H
#define XDP_NGAP_EVENT_H

/*
 * xdp_ngap_event.h — event schema for xdp_ngap.c's "events" ringbuf.
 *
 * #include'd on both sides, exactly like sm_map.h is for sm_nodes/
 * sm_edges:
 *   - by xdp_ngap.c (BPF/CO-RE) to declare the ringbuf and fill records
 *   - by test/test_xdp.c (userspace, via libbpf's ring_buffer__new()) to
 *     interpret the same bytes read back off that ringbuf
 *
 * xdp_ngap.c previously reported each NGAP DATA chunk via bpf_printk(),
 * visible only via `sudo cat /sys/kernel/debug/tracing/trace_pipe`. This
 * struct is what replaced that: a real event record, submitted through a
 * BPF_MAP_TYPE_RINGBUF the userspace loader polls and prints directly --
 * same mechanism amf_tracer.bpf.c's `events` ringbuf + amf_loader.c's
 * ring_buffer__poll() loop already use for the uprobe/tracepoint tracer,
 * just a private ringbuf+record type for this one XDP program instead of
 * the shared struct event (which is amf_tracer.bpf.c's own uprobe/
 * tracepoint schema and doesn't fit an SCTP/NGAP packet's fields).
 */

struct ngap_event {
    __u32 saddr;          /* source IPv4, network byte order (iph->saddr) */
    __u32 daddr;           /* dest IPv4, network byte order (iph->daddr) */
    __u16 sport;            /* SCTP source port, HOST byte order (already bpf_ntohs()'d) */
    __u16 dport;            /* SCTP dest port, HOST byte order */
    __u16 chunk_len;        /* SCTP DATA chunk length, HOST byte order */
    __u16 procedure_code;   /* NGAP procedureCode, HOST byte order */
    __u8  criticality;      /* NGAP criticality byte, as-is off the wire */
    __u8  _pad[3];          /* explicit alignment padding -- keep zeroed */
};

#endif /* XDP_NGAP_EVENT_H */
