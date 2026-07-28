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
#   sm_use_case        - narrates the README's "Detecting an Invalid State
#                        Transition" demo end-to-end (T0-T4 normal
#                        registration, T5 attack) against real, pinned
#                        maps left behind for `bpftool map dump` afterward.
#   test_xdp           - auto-attaching loader + detach watchdog for
#                        ../xdp_ngap.c: waits for veth5538fab to exist,
#                        attaches xdp_prog, then polls and ALERTs if it's
#                        ever detached/replaced/the interface disappears.
#                        Long-running (Ctrl+C to stop) -- NOT part of
#                        `make test`'s pass/fail loop, see WATCH_BINS.

CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -Wno-unused-parameter
LIBS     := -lbpf -lelf -lz

CLANG      := clang
ARCH       := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

BINS       := test_map_create test_map_walk sm_use_case
WATCH_BINS := test_xdp

SM_USE_CASE_PINS := /sys/fs/bpf/sm_use_case_nodes /sys/fs/bpf/sm_use_case_edges

.PHONY: all test clean clean-pins check-linux

all: check-linux $(BINS) $(WATCH_BINS)

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

sm_use_case: sm_use_case.c framework.h test_util.h fixtures.h ../sm_map.h
	$(CC) $(CFLAGS) sm_use_case.c -o $@ $(LIBS)

# The BPF object test_xdp.c loads at runtime (bpf_object__open_file()) --
# not linked in, so it's a separate build step, same clang -target bpf
# invocation ../README.md documents for hand-compiling xdp_ngap.c, just
# with its output kept in amf/test/ instead of amf/.
xdp_ngap.bpf.o: ../xdp_ngap.c ../xdp_ngap_event.h ../../vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c ../xdp_ngap.c -o $@

test_xdp: test_xdp.c ../xdp_ngap_event.h xdp_ngap.bpf.o
	$(CC) $(CFLAGS) test_xdp.c -o $@ $(LIBS)

clean:
	rm -f $(BINS) $(WATCH_BINS) xdp_ngap.bpf.o

# sm_use_case deliberately leaves its maps pinned at bpffs after running
# (see its file header comment) so they can be inspected with `bpftool
# map dump pinned ...`; this removes them once you're done looking.
clean-pins:
	sudo rm -f $(SM_USE_CASE_PINS)
