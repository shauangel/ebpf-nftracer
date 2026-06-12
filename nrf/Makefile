NF              := nrf

CLANG           := clang
CC              := gcc
BPFTOOL         := bpftool

ARCH            := $(shell uname -m | sed 's/x86_64/x86/')
KERNEL_SRC      := /lib/modules/$(shell uname -r)/build

CFLAGS          := -O2 -g -Wall
BPF_CFLAGS      := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

INCLUDES        := -I. -I.. -I$(KERNEL_SRC)/usr/include
LIBS            := -lbpf -lelf -lz

BPF_SRC         := $(NF)_tracer.bpf.c
BPF_OBJ         := $(NF)_tracer.bpf.o
SKEL_HDR        := $(NF)_tracer.skel.h

USER_SRCS       := $(NF)_loader.c $(NF)_comm.c $(NF)_functions.c
USER_OBJS       := $(USER_SRCS:.c=.o)

COMMON_OBJ      := ../common.o

TARGET          := $(NF)_loader

.PHONY: all clean

all: $(TARGET)

# Build the shared common object from the parent directory.
$(COMMON_OBJ): ../common.c ../common.h
	$(CC) $(CFLAGS) -I.. -c $< -o $@

$(TARGET): $(SKEL_HDR) $(USER_OBJS) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $(USER_OBJS) $(COMMON_OBJ) -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC) ../vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

$(SKEL_HDR): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f $(TARGET) $(USER_OBJS) $(BPF_OBJ) $(SKEL_HDR) $(COMMON_OBJ)
