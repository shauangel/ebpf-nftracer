// sm_map.c — the 23-state (+6 endpoint) threat-aware AMF FSM, stored as
// two CO-RE eBPF hash maps (BPF_MAP_TYPE_HASH):
//
//   sm_nodes   node name                    -> kind (normal/failure/endpoint)
//   sm_edges   (from state, event label)    -> to state
//
// Meant to be #included into a BPF compilation unit, NOT compiled as a
// standalone .bpf.o -- currently #include'd by BOTH amf_tracer.bpf.c (the
// uprobe/tracepoint tracer) and amf_xdp.c (the XDP packet-enforcement
// program), which are two SEPARATE BPF objects, independently loaded and
// attached. The sm_nodes/sm_edges maps below are pinned (see below) so
// both objects share the one populated instance rather than each getting
// its own empty copy. Built against ../vmlinux.h for all base
// types and BPF map-type constants (BTF-typed __uint()/__type() maps),
// exactly like amf_tracer.bpf.c's other SEC(".maps") definitions -- same
// CO-RE toolchain, same clang -target bpf compilation unit. sm_node_key /
// sm_edge_key are program-defined structs, not kernel structs, so no
// BPF_CORE_READ() field relocation is needed for them specifically; CO-RE
// here means "compiled against vmlinux.h/BTF", matching the rest of this
// BPF object.
//
// A BPF_MAP_TYPE_HASH has no static-initializer mechanism -- both maps
// start EMPTY at program load. The 29 nodes / 52 edges (mirrored from
// amf/amf_state_machine.py) are inserted at runtime by the userspace
// loader via bpf_map__update_elem(); see sm_map_populate() in
// amf_comm.c/amf_comm.h, called once from amf_loader.c right after
// amf_tracer_bpf__open_and_load().

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "sm_map.h"

/* Pinned (LIBBPF_PIN_BY_NAME -> /sys/fs/bpf/sm_nodes, /sys/fs/bpf/sm_edges)
 * so that amf_xdp.c -- a SEPARATE BPF object, attached independently via
 * XDP, not part of amf_tracer.bpf.o's skeleton -- can #include this same
 * file and resolve to the SAME kernel map instance instead of creating
 * its own empty copy. Whichever object loads first creates+pins the map;
 * amf_tracer.bpf.o's loader (amf_loader.c, via sm_map_populate()) is
 * expected to run first and own the actual population. Requires bpffs
 * mounted at /sys/fs/bpf (standard on any modern eBPF-capable system) --
 * without it, object load fails outright rather than silently skipping
 * the pin. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SM_NODE_MAP_MAX_ENTRIES);
    __type(key,   struct sm_node_key);
    __type(value, struct sm_node_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sm_nodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SM_EDGE_MAP_MAX_ENTRIES);
    __type(key,   struct sm_edge_key);
    __type(value, struct sm_edge_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sm_edges SEC(".maps");

/* ── In-kernel lookup helpers ──────────────────────────────────────────────
 * `name`/`from`/`label` are expected to be compile-time string literals
 * baked into this BPF program's own .rodata (e.g.
 * sm_node_lookup("REG_RECEIVED") called from inside a uprobe handler) --
 * copying them is a plain local read, not a bpf_probe_read from user/
 * kernel memory. Destination key buffers are zero-initialized first
 * (= {}) so unused tail bytes are always zero, matching what the
 * userspace loader writes -- BPF hash-map keys compare the full
 * fixed-size struct byte-for-byte, not a NUL-terminated string, so
 * inconsistent padding between writer and reader would silently break
 * every lookup.
 * ────────────────────────────────────────────────────────────────────── */

static __always_inline void sm_key_set_name(char dst[SM_NAME_MAX], const char *src)
{
    int i;
#pragma unroll
    for (i = 0; i < SM_NAME_MAX - 1 && src[i]; i++)
        dst[i] = src[i];
}

static __always_inline void sm_key_set_label(char dst[SM_LABEL_MAX], const char *src)
{
    int i;
#pragma unroll
    for (i = 0; i < SM_LABEL_MAX - 1 && src[i]; i++)
        dst[i] = src[i];
}

static __always_inline struct sm_node_val *sm_node_lookup(const char *name)
{
    struct sm_node_key key = {};
    sm_key_set_name(key.name, name);
    return bpf_map_lookup_elem(&sm_nodes, &key);
}

/* Validate a state transition in-kernel: given the state we believe the UE
 * is currently in and the event label just observed, return the FSM's
 * expected next state, or NULL if (from,label) is not a valid edge --
 * callers can treat a NULL return as its own threat signal (an
 * out-of-spec transition) right at the uprobe, before the event even
 * reaches userspace. */
static __always_inline struct sm_edge_val *sm_transition_lookup(const char *from,
                                                                  const char *label)
{
    struct sm_edge_key key = {};
    sm_key_set_name(key.from, from);
    sm_key_set_label(key.label, label);
    return bpf_map_lookup_elem(&sm_edges, &key);
}
