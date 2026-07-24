# amf/test/Makefile — host-side unit tests. No BPF toolchain, no libbpf,
# no root: everything here compiles and runs on any plain C toolchain.
#
#   test_sm_map        - sm_map.c's own logic (key encoding, lookups),
#                         small hand-written fixtures.
#   test_sm_map_data   - data-integrity checks on the REAL FSM table
#                         (sm_map_data.c) that amf_comm.c actually loads.
#   test_sm_fsm_walk   - real sm_map.c logic + real sm_map_data.c table,
#                         walking actual FSM state transitions.
#
# test_sm_map.c/test_sm_fsm_walk.c #include sm_map.c directly (see
# shim/bpf/bpf_helpers.h for why) rather than linking against a built
# object, so this suite is independent of the top-level Makefile.

CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -Wno-unknown-attributes -Wno-unused-parameter -Ishim

.PHONY: test clean

BINS := test_sm_map.bin test_sm_map_data.bin test_sm_fsm_walk.bin

test: $(BINS)
	@status=0; \
	for t in $(BINS); do \
		echo "== $$t =="; \
		./$$t || status=1; \
	done; \
	exit $$status

test_sm_map.bin: test_sm_map.c shim/bpf/bpf_helpers.h framework.h ../sm_map.c ../sm_map.h
	$(CC) $(CFLAGS) test_sm_map.c -o $@

test_sm_map_data.bin: test_sm_map_data.c framework.h ../sm_map_data.c ../sm_map_data.h ../sm_map.h
	$(CC) $(CFLAGS) test_sm_map_data.c ../sm_map_data.c -o $@

test_sm_fsm_walk.bin: test_sm_fsm_walk.c shim/bpf/bpf_helpers.h framework.h ../sm_map.c ../sm_map.h ../sm_map_data.c ../sm_map_data.h
	$(CC) $(CFLAGS) test_sm_fsm_walk.c ../sm_map_data.c -o $@

clean:
	rm -f $(BINS)
