# amf/test/Makefile — real eBPF tests for sm_map.c's sm_nodes/sm_edges
# BPF_MAP_TYPE_HASH maps. Unlike a host-side unit test, these create,
# populate, and iterate ACTUAL kernel BPF maps via libbpf -- so, unlike
# the mock-based suite this replaced, this one only builds/runs on Linux
# with CONFIG_BPF_SYSCALL and libbpf-dev installed, and the resulting
# binaries must be run as root (CAP_BPF/CAP_SYS_ADMIN) since they exercise
# the real bpf() syscall. See README.md for details on each test case.
#
#   test_map_create   - creates sm_nodes/sm_edges with sm_map.h's exact
#                        layout, checks kernel-reported map info, capacity
#                        enforcement, and the pin/reopen sharing mechanism
#                        sm_map.c depends on.
#   test_map_walk     - populates the real 29-node/52-edge FSM table
#                        (fixtures.h) and visits it via
#                        bpf_map_get_next_key()/bpf_map_lookup_elem(),
#                        plus point lookups and delete.

CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -Wno-unused-parameter
LIBS     := -lbpf -lelf -lz

BINS := test_map_create test_map_walk

.PHONY: test clean check-linux

check-linux:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "amf/test requires Linux + eBPF (bpf() syscall); refusing to build on $$(uname -s)."; \
		exit 1; \
	fi

# Builds the binaries and runs them. Each binary checks for root itself
# (see require_root() in test_util.h) and prints a clear message instead
# of reporting misleading EPERM failures per-check; run as
# `sudo make test` (or build with `make`, then `sudo ./test_map_create`
# etc.) on a real target machine.
test: check-linux $(BINS)
	@status=0; \
	for t in $(BINS); do \
		echo "== $$t =="; \
		./$$t || status=1; \
	done; \
	exit $$status

test_map_create: test_map_create.c framework.h test_util.h ../sm_map.h
	$(CC) $(CFLAGS) test_map_create.c -o $@ $(LIBS)

test_map_walk: test_map_walk.c framework.h test_util.h fixtures.h ../sm_map.h
	$(CC) $(CFLAGS) test_map_walk.c -o $@ $(LIBS)

clean:
	rm -f $(BINS)
