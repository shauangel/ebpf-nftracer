#ifndef MOCK_BPF_H
#define MOCK_BPF_H

/*
 * mock_bpf.h — host-side stand-in for <bpf/bpf_helpers.h>, used ONLY to
 * unit test sm_map.c on a plain userspace toolchain (no clang -target bpf,
 * no libbpf, no root, no kernel).
 *
 * sm_map.c is #include'd directly (never linked) by test_sm_map.c after
 * this header. Its own "../vmlinux.h" include resolves to the real
 * repo-root vmlinux.h (a quoted relative include always wins over -I), and
 * that already defines every kernel BTF type sm_map.c needs (including
 * enum bpf_map_type, i.e. BPF_MAP_TYPE_HASH) -- pure typedefs/structs, no
 * BPF-target-specific syntax, so it compiles fine with a normal host
 * clang/gcc. What's missing on a machine without libbpf installed is just
 * the SEC()/__uint()/__type() map-definition macros and the
 * bpf_map_lookup_elem() helper -- this header supplies those, matching
 * libbpf's own definitions closely enough that sm_nodes/sm_edges remain
 * ordinary (if functionally inert) global structs.
 *
 * bpf_map_lookup_elem() itself is only PROTOTYPED here; test_sm_map.c
 * defines its body after including sm_map.c, once sm_nodes/sm_edges exist
 * as real addresses it can dispatch on.
 */

#ifndef SEC
#define SEC(name)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Same shape as libbpf's bpf_helpers.h: encode type/size/pinning as the
 * pointee of an otherwise-unused struct member so the map-definition
 * struct stays a normal (if never-instantiated-for-real) global. */
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

void *bpf_map_lookup_elem(void *map, const void *key);

#endif /* MOCK_BPF_H */
