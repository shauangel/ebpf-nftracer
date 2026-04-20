CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -D__USER_SPACE__
BPF_CFLAGS := -O2 -g -target bpf \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-D__TARGET_ARCH_x86

LIBS := -lbpf -lelf -lz

NF = nrf
TARGET = $(NF)_loader
BPF_OBJ = $(NF)_tracer.bpf.o
SKEL = $(NF)_tracer.skel.h

all: $(TARGET)

# 1. compile eBPF program
$(BPF_OBJ): $(NF)_tracer.bpf.c events.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# 2. generate skeleton
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 3. compile user space
$(TARGET): $(NF)_loader.c common.c $(SKEL)
	$(CLANG) $(CFLAGS) -D__USER_SPACE__ $(NF)_loader.c common.c -o $@ $(LIBS)
clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL)