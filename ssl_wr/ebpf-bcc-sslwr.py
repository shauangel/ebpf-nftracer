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

    char target[SIG_LEN] = "00000000000000000000000000000000";
    char inject[SIG_LEN] = "ebpf-injected-signature-000001";

    int scan_len = frame_len;
    if (scan_len > MAX_SCAN)
        scan_len = MAX_SCAN;

    for (int i = 0; i <= MAX_SCAN - SIG_LEN; i++) {
        if (i > scan_len - SIG_LEN)
            break;

        char cand[SIG_LEN];
        bpf_probe_read_user(cand, SIG_LEN, buf + 9 + i);

        int matched = 1;

#pragma unroll
        for (int j = 0; j < SIG_LEN; j++) {
            if (cand[j] != target[j]) {
                matched = 0;
                break;
            }
        }

        if (matched) {
            bpf_probe_write_user(buf + 9 + i, inject, SIG_LEN);
            bpf_trace_printk("inject offset=%d\\n", i);
            break;
        }
    }

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