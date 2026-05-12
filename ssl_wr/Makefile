CLANG   ?= clang
CC      ?= gcc
ARCH    ?= x86

BPF_CFLAGS  := -O2 -g -Wall -Werror -target bpf \
               -D__TARGET_ARCH_$(ARCH) \
               -I/usr/include/x86_64-linux-gnu \
               -I.

HOST_CFLAGS := -O2 -Wall -Wextra -I. -I/usr/include/bpf
LDFLAGS     := -lbpf -lelf -lz

.PHONY: all clean check-tools

all: nrf_read_loader

# ── Step 0: generate vmlinux.h from the running kernel's BTF ─────────────────
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── Step 1: compile BPF C → BPF ELF object ───────────────────────────────────
nrf_read.bpf.o: nrf_read.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	# Sanity check — list what programs are inside the object:
	llvm-objdump -d $@ | grep -E "^<|Disasm" || true

# ── Step 2: generate C skeleton from BPF object ───────────────────────────────
nrf_read.skel.h: nrf_read.bpf.o
	bpftool gen skeleton $< > $@

# ── Step 3: build the C loader ────────────────────────────────────────────────
nrf_read_loader: nrf_read_loader.c nrf_read.skel.h
	$(CC) $(HOST_CFLAGS) $< -o $@ $(LDFLAGS)

# ── Helper: rebuild NRF with no inlining so uprobe symbols survive ────────────
nrf-build:
	@test -n "$(NRF_SRC)" || (echo "Set NRF_SRC= to the free5gc/NRF directory" && exit 1)
	cd $(NRF_SRC) && go build \
	    -gcflags="all=-l" \
	    -ldflags="-compressdwarf=false" \
	    -trimpath=false \
	    -o nrf ./cmd/nrf/

check-tools:
	@which clang      >/dev/null || echo "MISSING: clang"
	@which bpftool    >/dev/null || echo "MISSING: bpftool"
	@which llvm-strip >/dev/null || echo "MISSING: llvm-strip"
	@ls /sys/kernel/btf/vmlinux >/dev/null || echo "MISSING: kernel BTF"

clean:
	rm -f vmlinux.h nrf_read.bpf.o nrf_read.skel.h nrf_read_loader