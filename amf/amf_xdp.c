// amf_xdp.c
//
// XDP packet ENFORCEMENT for the AMF's N2 (NGAP/SCTP) ingress -- extends
// amf/xdp_ngap.c's parse-and-log logic with an active drop path, and now
// cross-checks every categorized packet against the threat-aware FSM
// (amf/sm_map.c) via a per-source UE-state map.
//
// Main procedure, per SCTP/NGAP packet:
//   1. Parse Ethernet/IP/SCTP down to the NGAP procedureCode (unchanged
//      from xdp_ngap.c's approach).
//   2. Categorize the procedure code into an FSM edge label via
//      ngap_procedure_label() -- TODO: only a handful of codes are mapped
//      so far (see that function); everything else is passed through
//      with no FSM check, exactly like before this change.
//   3. Look up this source's current FSM state in ue_state_map (defaults
//      to the FSM's own "UE/gNB" endpoint node if never seen).
//   4. Ask sm_edges (via sm_transition_lookup(), from sm_map.c) whether
//      (current_state, label) is a valid edge. Valid -> advance
//      ue_state_map to the edge's destination state. Invalid -> flag it
//      (log + STAT_STATE_INVALID) as an out-of-spec transition -- NOT
//      dropped yet (see "Enforcement policy" below).
//
// Enforcement policy (what actually returns XDP_DROP today):
//   Per-source-IP rate limiting on NGAP InitialUEMessage remains the only
//   hard drop trigger. FSM-mismatch is observability only for now,
//   because categorization is still partial (step 2) and the UE key is
//   still an approximation (see "TODO" on ue_key below) -- promoting a
//   sparse/approximate signal straight to XDP_DROP risks false positives
//   on real traffic. Once procedure-code coverage and UE keying improve,
//   this is the one place to change (see the comment at the mismatch
//   branch in amf_xdp_enforce()).
//
// InitialUEMessage (procedureCode = id-InitialUEMessage = 15, 3GPP TS
// 38.413 NGAP-Constants) is the unauthenticated message that starts UE
// registration (REG_RECEIVED in amf/amf_state_machine.py /
// amf/doc/ebpf-hook-point.pdf) -- cheap for an attacker to send, expensive
// for the AMF to process (RanUe + AmfUe context creation, NAS decode),
// which makes it the classic N2-interface flood/DoS vector. The PDF's own
// recommendation explicitly reserves XDP for exactly this: "a separate,
// lower-layer signal (raw SCTP flood/DoS detection on the N2 interface)
// that this state graph does not model."
//
// Fail-open by design: any packet this program can't confidently parse or
// categorize (non-IP, non-SCTP, non-NGAP, truncated/malformed, or an
// uncategorized NGAP procedure) is passed through unmodified.
//
// sm_nodes/sm_edges sharing: sm_map.c pins those two maps
// (LIBBPF_PIN_BY_NAME), so this object resolves to the SAME populated
// maps that amf_tracer.bpf.o's loader (amf_loader.c, via
// sm_map_populate()) creates and fills -- this object never writes to
// them, only reads. ue_state_map below is NOT pinned/shared (yet); it's
// private to this object.
//
// Attach target: veth5538fab (host-side veth of the AMF container's N2
// interface).
//   Attach : sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
//   Detach : sudo ip link set dev veth5538fab xdp off
//   Verify : ip link show dev veth5538fab      (look for "prog/xdp id ...")
//   Stats  : bpftool map dump name amf_xdp_stats
//   UE map : bpftool map dump name ue_state_map
//   Build  : clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I.. -c amf_xdp.c -o amf_xdp.o
//   Note   : requires bpffs mounted at /sys/fs/bpf (for sm_nodes/sm_edges
//            pinning) and amf_loader.c already running at least once so
//            sm_nodes/sm_edges exist and are populated -- if this object
//            loads first, it creates+pins them EMPTY and every FSM lookup
//            below will simply miss until the tracer loader populates them.

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Threat-aware AMF FSM: sm_nodes / sm_edges (pinned, shared with
 * amf_tracer.bpf.o) + sm_node_lookup() / sm_transition_lookup() /
 * sm_key_set_name() helpers. See amf/sm_map.c. */
#include "sm_map.c"

#define ETH_P_IP        0x0800
#define IPPROTO_SCTP    132
#define SCTP_PPID_NGAP  60
#define SCTP_DATA       0

/* 3GPP TS 38.413 NGAP-Constants: id-InitialUEMessage */
#define NGAP_PROC_INITIAL_UE_MESSAGE 15

/* Rate-limit window and threshold for InitialUEMessage, per source IP. A
 * legitimate gNB serves many UEs but not at this rate from one address;
 * tune RATE_MAX_PER_WIN to the deployment's expected registration rate. */
#define RATE_WINDOW_NS    (1000000000ULL)   /* 1 second */
#define RATE_MAX_PER_WIN  50

struct sctphdr_simple {
    __u16 source;
    __u16 dest;
    __u32 vtag;
    __u32 checksum;
};

struct sctp_data_chunk {
    __u8  type;
    __u8  flags;
    __u16 length;
    __u32 tsn;
    __u16 stream_id;
    __u16 stream_seq;
    __u32 ppid;
};

struct rate_entry {
    __u64 window_start_ns;
    __u32 count;
};

char LICENSE[] SEC("license") = "GPL";

/* Per-source-IP InitialUEMessage counters. LRU so a spread of distinct
 * attacker IPs ages out old entries instead of exhausting the map. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);             /* source IPv4, network order */
    __type(value, struct rate_entry);
} amf_xdp_rate_map SEC(".maps");

/* Pass/drop/mismatch counters, readable from userspace (e.g.
 * `bpftool map dump`) without needing a ring-buffer consumer. */
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key,   __u32);
    __type(value, __u64);
} amf_xdp_stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&amf_xdp_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ── Per-UE FSM state (private to this object, not pinned) ───────────────
 * TODO: keyed on source IPv4 as a stand-in UE identity -- collides every
 * UE behind the same gNB/NAT address into one entry. Replace with
 * RAN-UE-NGAP-ID (an NGAP IE, ASN.1 PER-encoded) once this program parses
 * far enough into the PDU to extract it; that's real per-UE granularity,
 * this is a placeholder good enough for a single-gNB test lab.
 * ────────────────────────────────────────────────────────────────────── */

struct ue_val {
    char  state[SM_NAME_MAX];   /* current FSM node name, e.g. "REG_RECEIVED" */
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);        /* TODO: RAN-UE-NGAP-ID; source IPv4 for now */
    __type(value, struct ue_val);
} ue_state_map SEC(".maps");

static __always_inline struct ue_val *ue_state_lookup(__u32 key)
{
    return bpf_map_lookup_elem(&ue_state_map, &key);
}

static __always_inline void ue_state_set(__u32 key, const char *state, __u64 now)
{
    struct ue_val val = {};
    sm_key_set_name(val.state, state);   /* bounded copy, from sm_map.c */
    val.last_seen_ns = now;
    bpf_map_update_elem(&ue_state_map, &key, &val, BPF_ANY);
}

/* ── NGAP procedureCode -> FSM edge label ─────────────────────────────────
 * TODO: only InitialUEMessage is categorized so far. Expanding this to
 * cover more of amf_state_machine.py's 52 edges needs deeper per-procedure
 * NGAP IE parsing than this file currently does -- and several edges
 * (e.g. "AUSF success", "integrity fail") aren't NGAP-visible at all,
 * they're internal AMF<->AUSF/UDM/PCF SBI outcomes the uprobe tracer sees
 * instead (see amf_tracer.bpf.c). Returns NULL for anything not yet
 * categorized; callers must treat NULL as "no verdict, pass" rather than
 * "invalid" -- an unmapped procedure code says nothing about legitimacy.
 * ────────────────────────────────────────────────────────────────────── */
static __always_inline const char *ngap_procedure_label(__u16 procedure_code)
{
    switch (procedure_code) {
    case NGAP_PROC_INITIAL_UE_MESSAGE:
        return "InitialUEMessage";
    default:
        return (const char *)0;   /* TODO: categorize remaining procedures */
    }
}

/* Returns 1 if src_ip has exceeded the InitialUEMessage rate limit (caller
 * must drop), 0 otherwise (this call has already accounted the packet
 * into the current window). */
static __always_inline int rate_limited(__u32 src_ip, __u64 now)
{
    struct rate_entry *e = bpf_map_lookup_elem(&amf_xdp_rate_map, &src_ip);
    if (!e) {
        struct rate_entry init = { .window_start_ns = now, .count = 1 };
        bpf_map_update_elem(&amf_xdp_rate_map, &src_ip, &init, BPF_ANY);
        return 0;
    }

    if (now - e->window_start_ns > RATE_WINDOW_NS) {
        e->window_start_ns = now;
        e->count = 1;
        return 0;
    }

    e->count++;
    return e->count > RATE_MAX_PER_WIN;
}

SEC("xdp")
int amf_xdp_enforce(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet + IPv4 only
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
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

    if (chunk->type != SCTP_DATA)
        return XDP_PASS;
    if (bpf_ntohl(chunk->ppid) != SCTP_PPID_NGAP)
        return XDP_PASS;

    // NGAP PDU: first two bytes are the procedureCode
    void *ngap = (void *)(chunk + 1);
    if (ngap + 16 > data_end)
        return XDP_PASS;

    __u8  b0 = *(__u8 *)(ngap + 0);
    __u8  b1 = *(__u8 *)(ngap + 1);
    __u16 procedure_code = ((__u16)b0 << 8) | b1;

    // Step 2: categorize (TODO: partial coverage, see ngap_procedure_label())
    const char *label = ngap_procedure_label(procedure_code);
    if (!label) {
        bump_stat(STAT_PASS);
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 src_ip = iph->saddr;

    // Step 3: this source's current FSM state (default: the FSM's own
    // "UE/gNB" endpoint node, for a source we've never categorized before)
    struct ue_val *ue = ue_state_lookup(src_ip);
    const char *from_state = ue ? ue->state : "UE/gNB";

    // Step 4: is (from_state, label) a valid edge in sm_edges?
    struct sm_edge_val *edge = sm_transition_lookup(from_state, label);
    if (edge) {
        ue_state_set(src_ip, edge->to, now);
    } else {
        // Out-of-spec transition -- e.g. a source already past
        // REGISTERED_CONNECTED sending another InitialUEMessage. Flagged,
        // not dropped: see "Enforcement policy" in the file header for
        // why this isn't XDP_DROP yet.
        bpf_printk("amf_xdp: FSM mismatch src=0x%x label=%s",
                   bpf_ntohl(src_ip), label);
        bump_stat(STAT_STATE_INVALID);
    }

    // Enforcement: rate-limit InitialUEMessage regardless of FSM verdict
    // above (today's only hard drop trigger -- see file header).
    if (procedure_code == NGAP_PROC_INITIAL_UE_MESSAGE &&
        rate_limited(src_ip, now)) {
        bpf_printk("amf_xdp: DROP InitialUEMessage flood src=0x%x", bpf_ntohl(src_ip));
        bump_stat(STAT_DROP);
        return XDP_DROP;
    }

    bump_stat(STAT_PASS);
    return XDP_PASS;
}
