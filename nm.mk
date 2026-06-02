# Makefile — namespace_tracer (socket-level edition)
#
# Build pipeline:
#   1. bpftool btf dump  →  vmlinux.h
#   2. clang -target bpf  →  namespace_tracer.bpf.o
#   3. bpftool gen skeleton  →  namespace_tracer.skel.h
#   4. gcc  →  namespace_tracer

CC      := gcc
CLANG   := clang
BPFTOOL := bpftool

BPF_CFLAGS := \
    -g -O2 \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I.

USR_CFLAGS  := -g -O2 -Wall -Wextra -I.
USR_LDFLAGS := -lbpf -lelf -lz

.PHONY: all run clean

all: namespace_tracer

vmlinux.h:
	@echo "[1/4] Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

namespace_tracer.bpf.o: namespace_tracer.bpf.c vmlinux.h
	@echo "[2/4] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c namespace_tracer.bpf.c -o namespace_tracer.bpf.o

namespace_tracer.skel.h: namespace_tracer.bpf.o
	@echo "[3/4] Generating skeleton..."
	$(BPFTOOL) gen skeleton namespace_tracer.bpf.o > namespace_tracer.skel.h

namespace_tracer: namespace_tracer.c namespace_tracer.skel.h
	@echo "[4/4] Compiling loader..."
	$(CC) $(USR_CFLAGS) namespace_tracer.c $(USR_LDFLAGS) -o namespace_tracer
	@echo ""
	@echo "  sudo ./namespace_tracer"
	@echo "  sudo ./namespace_tracer --no-colour 2>/dev/null | tee trace.log"

run: all
	sudo ./namespace_tracer

clean:
	rm -f namespace_tracer namespace_tracer.bpf.o namespace_tracer.skel.h vmlinux.h
