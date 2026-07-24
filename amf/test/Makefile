# amf/test/Makefile — real eBPF tests for sm_map.c's sm_nodes/sm_edges
# BPF_MAP_TYPE_HASH maps. Unlike a host-side unit test, these create,
# populate, and iterate ACTUAL kernel BPF maps via libbpf -- so, unlike
# the mock-based suite this replaced, this one only builds/runs on Linux
# with CONFIG_BPF_SYSCALL and libbpf-dev installed, and the resulting
# binaries must be run as root (CAP_BPF/CAP_SYS_ADMIN) since they exercise
# the real bpf() syscall. See doc_map_test.md / doc_xdp_test.md for
# details on each test case.
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
#   test_xdp           - live MONITOR (not an automated test -- see
#                        MONITOR_BINS below) for the real ../amf_xdp.c
#                        (built here as amf_xdp.o, see the amf_xdp.o rule
#                        below): attaches it to a real interface and
#                        prints amf_xdp_stats/ue_state_map as real traffic
#                        crosses it. See doc_xdp_test.md.

CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -Wno-unused-parameter
LIBS     := -lbpf -lelf -lz

CLANG      := clang
ARCH       := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

# Binaries that run to completion on their own -- what `make test` builds
# and runs automatically.
TEST_BINS := test_map_create test_map_walk sm_use_case

# test_xdp is a long-running live monitor: it attaches to a real interface
# and runs until Ctrl+C. Built by `make`/`make all` like everything else,
# but deliberately EXCLUDED from `make test`'s automated run loop -- it
# would just hang that loop forever. Run it by hand:
# `sudo ./test_xdp [ifname]`.
MONITOR_BINS := test_xdp

BINS := $(TEST_BINS) $(MONITOR_BINS)

SM_USE_CASE_PINS := /sys/fs/bpf/sm_use_case_nodes /sys/fs/bpf/sm_use_case_edges

.PHONY: all test clean clean-pins check-linux

# Default goal (bare `make`): build everything, run nothing.
all: check-linux $(BINS)

check-linux:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "amf/test requires Linux + eBPF (bpf() syscall); refusing to build on $$(uname -s)."; \
		exit 1; \
	fi

# Builds and runs TEST_BINS only (NOT test_xdp -- see MONITOR_BINS above).
# Each binary checks for root itself (see require_root() in test_util.h)
# and prints a clear message instead of reporting misleading EPERM
# failures per-check; run as `sudo make test` (or build with `make`, then
# `sudo ./test_map_create` etc.) on a real target machine.
test: check-linux $(TEST_BINS)
	@status=0; \
	for t in $(TEST_BINS); do \
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

test_xdp: test_xdp.c test_util.h fixtures.h ../sm_map.h amf_xdp.o
	$(CC) $(CFLAGS) test_xdp.c -o $@ $(LIBS)

# amf_xdp.o is a real compiled BPF object -- NOT linked into test_xdp,
# loaded at RUNTIME via bpf_object__open_file(). ../amf_xdp.c has never
# had a build rule of its own (see its header comment: historically
# hand-compiled with the command documented in ../README.md); this rule
# builds it HERE, into amf/test/, so nothing is written into ../ (the
# parent amf/ directory).
amf_xdp.o: ../amf_xdp.c ../sm_map.c ../sm_map.h ../../vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I.. -I../.. -c ../amf_xdp.c -o $@

clean:
	rm -f $(BINS) amf_xdp.o

# sm_use_case deliberately leaves its maps pinned at bpffs after running
# (see its file header comment) so they can be inspected with `bpftool
# map dump pinned ...`; this removes them once you're done looking.
clean-pins:
	sudo rm -f $(SM_USE_CASE_PINS)
