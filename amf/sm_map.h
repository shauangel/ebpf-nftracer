#ifndef SM_MAP_H
#define SM_MAP_H

/*
 * sm_map — key/value layouts for the 23-state (+6 endpoint) threat-aware
 * AMF FSM, stored as two real BPF_MAP_TYPE_HASH maps (see sm_map.c):
 *
 *   sm_nodes  key=struct sm_node_key{name}         val=struct sm_node_val{kind}
 *   sm_edges  key=struct sm_edge_key{from,label}    val=struct sm_edge_val{to}
 *
 * This header is included on BOTH sides, exactly like ../events.h's
 * struct event:
 *   - by sm_map.c (BPF/CO-RE, compiled with clang -target bpf against
 *     ../vmlinux.h) to declare the maps and do in-kernel lookups
 *   - by amf_comm.c (userspace, via libbpf) to build identical keys/values
 *     when populating the maps with bpf_map__update_elem() after skeleton
 *     load — see sm_map_populate() in amf_comm.h
 *
 * Keys/values are fixed-size, pointer-free structs (required for BPF map
 * key/value types), so the layout is valid unchanged in both translation
 * units. __u8 etc. resolve consistently on both sides (vmlinux.h on the
 * BPF side, linux/types.h via bpf/libbpf.h on the userspace side).
 */

#define SM_NAME_MAX  32
#define SM_LABEL_MAX 48

enum sm_node_kind {
    SM_KIND_NORMAL   = 0,   /* one of the 13 normal-path FSM states    */
    SM_KIND_FAILURE  = 1,   /* one of the 10 failure/threat FSM states */
    SM_KIND_ENDPOINT = 2,   /* external peer: UE/gNB, AMF, AUSF, UDM, PCF, SMF */
};

struct sm_node_key {
    char name[SM_NAME_MAX];        /* zero-padded; must be memset before use */
};

struct sm_node_val {
    __u8 kind;                     /* enum sm_node_kind */
};

struct sm_edge_key {
    char from[SM_NAME_MAX];        /* zero-padded; must be memset before use */
    char label[SM_LABEL_MAX];      /* zero-padded; must be memset before use */
};

struct sm_edge_val {
    char to[SM_NAME_MAX];
};

/* amf_state_machine.py has 29 nodes / 52 edges; headroom for growth */
#define SM_NODE_MAP_MAX_ENTRIES 64
#define SM_EDGE_MAP_MAX_ENTRIES 128

#endif /* SM_MAP_H */
