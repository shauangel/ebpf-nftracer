#ifndef SM_MAP_DATA_H
#define SM_MAP_DATA_H

/* size_t: skip <stddef.h> when vmlinux.h is already active in this
 * translation unit (e.g. test_sm_fsm_walk.c, which #includes sm_map.c --
 * and therefore vmlinux.h -- before this header). vmlinux.h's own BTF
 * dump already typedefs size_t (and, more to the point, wchar_t as a
 * kernel u16), and a later <stddef.h> redefining wchar_t as the host's
 * built-in type is a hard conflict, not just a redundant-but-compatible
 * redeclaration like __u8 below. */
#ifndef __VMLINUX_H__
#include <stddef.h>
#endif

/* sm_map.h's struct sm_node_val/sm_edge_val use __u8, which sm_map.h
 * deliberately leaves for the includer to provide -- vmlinux.h on the
 * BPF side, linux/types.h via bpf/libbpf.h on amf_comm.c's userspace
 * side (see sm_map.h's own top comment). sm_map_data.c is a standalone
 * translation unit that goes through neither chain on its own (it's
 * linked into amf_loader, but compiled separately), so provide the same
 * type here, portably. Guarded against both real chains already having
 * defined it (typedef names aren't independently guardable, so this
 * keys off their known include guards instead). */
#if !defined(__VMLINUX_H__) && !defined(_LINUX_TYPES_H)
#include <stdint.h>
typedef uint8_t __u8;
#endif

#include "sm_map.h"

/*
 * sm_map_data.h / sm_map_data.c — the 29-node / 52-edge threat-aware AMF
 * FSM table, mirrored 1:1 from amf_state_machine.py (see sm_map.c's
 * top-of-file comment for the full picture).
 *
 * Split out of amf_comm.c so this data has exactly one definition that
 * both the real loader (amf_comm.c's sm_map_populate(), which loads it
 * into the live BPF maps) and amf/test/'s unit tests (which load it into
 * a host-side mock instead) read from -- a change to the FSM here is what
 * both the running tracer and the test suite see, instead of a second
 * hand-copied table silently drifting out of sync.
 *
 * No BPF/libbpf dependency: only sm_map.h (itself dependency-free), so
 * this compiles on a plain host toolchain same as sm_map.c does under
 * amf/test/'s shim.
 */

struct sm_node_def { const char *name; enum sm_node_kind kind; };
struct sm_edge_def { const char *from, *to, *label; };

extern const struct sm_node_def sm_node_data[];
extern const size_t sm_node_data_count;

extern const struct sm_edge_def sm_edge_data[];
extern const size_t sm_edge_data_count;

#endif /* SM_MAP_DATA_H */
