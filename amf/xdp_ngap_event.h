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
 * just a private ringbuf for this one XDP program instead of the shared
 * struct event (amf_tracer.bpf.c's own uprobe/tracepoint schema).
 *
 * xdp_ngap.c now gathers two kinds of traffic on the same interface --
 * SCTP/NGAP (the original purpose) and, alongside it, plain TCP/HTTP --
 * so one record type has to represent both, same way struct event in
 * ../events.h represents EVT_API_CALL/EVT_CONNECT/EVT_WRITE/etc: a `type`
 * tag plus a comment documenting which fields apply to which type. All
 * fields not used by a given type are zeroed by xdp_ngap.c.
 */

#define XDP_EVT_NGAP 0   /* SCTP DATA chunk carrying an NGAP PDU (PPID 60) */
#define XDP_EVT_HTTP 1   /* TCP payload starting with a recognized HTTP/1.x request or response line */

/*
 * Field usage by type:
 *
 *   XDP_EVT_NGAP -> type, saddr, daddr, sport, dport, chunk_len,
 *                   procedure_code, criticality
 *   XDP_EVT_HTTP -> type, saddr, daddr, sport, dport, method
 */
struct xdp_event {
    __u8  type;              /* XDP_EVT_* */
    __u8  _pad[3];           /* explicit alignment padding -- keep zeroed */

    __u32 saddr;              /* source IPv4, network byte order (iph->saddr) */
    __u32 daddr;               /* dest IPv4, network byte order (iph->daddr) */
    __u16 sport;                /* source port, HOST byte order (already bpf_ntohs()'d) */
    __u16 dport;                 /* dest port, HOST byte order */

    __u16 chunk_len;              /* NGAP: SCTP DATA chunk length, HOST byte order */
    __u16 procedure_code;          /* NGAP: procedureCode, HOST byte order */
    __u8  criticality;               /* NGAP: criticality byte, as-is off the wire */

    char  method[8];                  /* HTTP: NUL-terminated request method, or "HTTP" for a response status line */
};

#endif /* XDP_NGAP_EVENT_H */
