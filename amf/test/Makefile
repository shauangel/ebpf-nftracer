# amf/test/Makefile — host-side unit tests. No BPF toolchain, no libbpf,
# no root: everything here compiles and runs on any plain C toolchain.
# Each test_*.c #includes its target .c file directly (see mock_bpf.h for
# why that's needed for sm_map.c specifically) rather than linking against
# built objects, so this suite is independent of the top-level Makefile.

CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -Wno-unknown-attributes -Wno-unused-parameter -Ishim

TESTS    := test_sm_map
BINS     := $(TESTS:%=%.bin)

.PHONY: test clean

test: $(BINS)
	@status=0; \
	for t in $(BINS); do \
		echo "== $$t =="; \
		./$$t || status=1; \
	done; \
	exit $$status

%.bin: %.c shim/bpf/bpf_helpers.h framework.h ../sm_map.c ../sm_map.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS)
