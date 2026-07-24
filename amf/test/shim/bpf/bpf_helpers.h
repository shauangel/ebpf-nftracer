#ifndef MOCK_BPF_HELPERS_H
#define MOCK_BPF_HELPERS_H

/*
 * shim/bpf/bpf_helpers.h — host-side stand-in for the real
 * <bpf/bpf_helpers.h>, used ONLY to unit test sm_map.c on a plain
 * userspace toolchain (no clang -target bpf, no libbpf, no root, no
 * kernel). Found transparently: sm_map.c does `#include <bpf/bpf_helpers.h>`
 * and the test Makefile puts this shim/ directory on -I ahead of anything
 * else providing that path, so this file resolves instead of the real one.
 *
 * sm_map.c also does `#include "../vmlinux.h"` first -- a quoted relative
 * include, which always resolves straight to the real repo-root vmlinux.h
 * regardless of -I. That's fine: it's pure typedefs/structs/enums (no
 * BPF-target-specific syntax), including enum bpf_map_type (so
 * BPF_MAP_TYPE_HASH needs no shim), so it compiles as-is with a normal
 * host clang/gcc. What's actually missing without libbpf installed is
 * just the SEC()/__uint()/__type() map-definition macros and the
 * bpf_map_lookup_elem() helper -- supplied below, matching libbpf's own
 * definitions closely enough that sm_nodes/sm_edges remain ordinary (if
 * functionally inert) global structs.
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
#define __type(name, val) __typeof__(val) *name
#endif

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

void *bpf_map_lookup_elem(void *map, const void *key);

#endif /* MOCK_BPF_HELPERS_H */
