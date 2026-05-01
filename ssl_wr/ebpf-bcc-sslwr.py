#!/usr/bin/env python3
from bcc import BPF
import argparse
import ctypes
import time

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_SCAN 256
#define SIG_LEN 32

static __always_inline int try_inject(void *pos) {
    char target[SIG_LEN] = "00000000000000000000000000000000";
    char inject[SIG_LEN] = "ebpf-injected-signature-000001";
    char cand[SIG_LEN];

    bpf_probe_read_user(cand, SIG_LEN, pos);

    int ok = 1;
#pragma unroll
    for (int j = 0; j < SIG_LEN; j++) {
        if (cand[j] != target[j])
            ok = 0;
    }

    if (ok) {
        bpf_probe_write_user(pos, inject, SIG_LEN);
        bpf_trace_printk("inject success\\n");
        return 1;
    }

    return 0;
}

int trace_ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len < 9)
        return 0;

    unsigned char hdr[9];
    bpf_probe_read_user(hdr, sizeof(hdr), buf);

    unsigned int frame_len =
        ((unsigned int)hdr[0] << 16) |
        ((unsigned int)hdr[1] << 8)  |
        ((unsigned int)hdr[2]);

    unsigned char frame_type = hdr[3];

    if (frame_type != 0x01)
        return 0;

    if (frame_len == 0 || frame_len > len - 9)
        return 0;

    void *payload = buf + 9;

    if (try_inject(payload + 0)) return 0;
    if (try_inject(payload + 16)) return 0;
    if (try_inject(payload + 32)) return 0;
    if (try_inject(payload + 48)) return 0;
    if (try_inject(payload + 64)) return 0;
    if (try_inject(payload + 80)) return 0;
    if (try_inject(payload + 96)) return 0;
    if (try_inject(payload + 112)) return 0;
    if (try_inject(payload + 128)) return 0;

    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", type=int, required=True)
parser.add_argument("--libssl", default="/usr/lib/x86_64-linux-gnu/libssl.so.3")
args = parser.parse_args()

b = BPF(text=BPF_SRC)
b.attach_uprobe(
    name=args.libssl,
    sym="SSL_write",
    fn_name="trace_ssl_write",
    pid=args.pid
)

print(f"[+] attached SSL_write uprobe pid={args.pid}")
print("[+] tracing... Ctrl-C to stop")

try:
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(msg.decode(errors="ignore"))
except KeyboardInterrupt:
    pass