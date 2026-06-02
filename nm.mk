# Makefile — namespace_tracer
#
# Build pipeline:
#   1. bpftool btf dump  →  vmlinux.h       (kernel type info for CO-RE)
#   2. clang -target bpf  →  *.bpf.o        (BPF bytecode)
#   3. bpftool gen skeleton  →  *.skel.h    (libbpf C skeleton)
#   4. gcc  →  namespace_tracer             (userspace loader)
#
# Usage:
#   make          — full build
#   make run      — build + run as root
#   make clean    — remove all generated files

# ── Tools ─────────────────────────────────────────────────────────────────────

CC       := gcc
CLANG    := clang
BPFTOOL  := bpftool

# ── Flags ─────────────────────────────────────────────────────────────────────

# BPF compilation flags.
# -g                  emit BTF debug info (required for skeleton + CO-RE)
# -O2                 BPF programs must be optimised (verifier rejects unoptimised)
# -target bpf         cross-compile for BPF virtual machine
# -D__TARGET_ARCH_x86 tell vmlinux.h which arch-specific types to expose
BPF_CFLAGS := \
    -g \
    -O2 \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I.

# Userspace compilation flags.
USR_CFLAGS  := -g -O2 -Wall -Wextra -I.
USR_LDFLAGS := -lbpf -lelf -lz

# ── Targets ───────────────────────────────────────────────────────────────────

.PHONY: all run clean

all: namespace_tracer

# Step 1 — extract full kernel type info as a C header.
# This is the CO-RE foundation: the BPF program compiles against these types
# and libbpf relocates field offsets to the actual running kernel at load time.
vmlinux.h:
	@echo "[1/4] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "      done."

# Step 2 — compile the BPF C program to BPF ELF bytecode.
namespace_tracer.bpf.o: namespace_tracer.bpf.c vmlinux.h
	@echo "[2/4] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c namespace_tracer.bpf.c -o namespace_tracer.bpf.o
	@echo "      done: namespace_tracer.bpf.o"

# Step 3 — generate the C skeleton from the BPF ELF.
# The skeleton embeds the BPF bytecode and exposes a typed API for:
#   - opening / loading / attaching the program
#   - accessing maps by name (skel->maps.container_cgroups, etc.)
namespace_tracer.skel.h: namespace_tracer.bpf.o
	@echo "[3/4] Generating BPF skeleton..."
	$(BPFTOOL) gen skeleton namespace_tracer.bpf.o > namespace_tracer.skel.h
	@echo "      done: namespace_tracer.skel.h"

# Step 4 — compile the C userspace loader.
namespace_tracer: namespace_tracer.c namespace_tracer.skel.h
	@echo "[4/4] Compiling userspace loader..."
	$(CC) $(USR_CFLAGS) namespace_tracer.c $(USR_LDFLAGS) -o namespace_tracer
	@echo "      done: ./namespace_tracer"
	@echo ""
	@echo "Run with: sudo ./namespace_tracer"
	@echo "Options:  -v (verbose libbpf)  --no-colour (plain output)"

# Convenience target — build and run immediately.
run: all
	sudo ./namespace_tracer

clean:
	rm -f namespace_tracer namespace_tracer.bpf.o \
	      namespace_tracer.skel.h vmlinux.h
	@echo "Cleaned."
