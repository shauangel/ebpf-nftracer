#!/usr/bin/env python3
from bcc import BPF
import argparse

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_SCAN 1024
#define TARGET_LEN 8

static const char target[TARGET_LEN] = "curlsig0";
static const char inject[TARGET_LEN] = "sig00001";

int trace_ssl_write(struct pt_regs *ctx)
{
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len < 9)
        return 0;

    unsigned char h2[9] = {};
    bpf_probe_read_user(h2, sizeof(h2), buf);

    unsigned int frame_len =
        ((unsigned int)h2[0] << 16) |
        ((unsigned int)h2[1] << 8)  |
        ((unsigned int)h2[2]);

    unsigned char frame_type = h2[3];

    // HTTP/2 HEADERS frame
    if (frame_type != 0x01)
        return 0;

    if (frame_len == 0)
        return 0;

    if (frame_len > len - 9)
        return 0;

    int scan_len = frame_len;
    if (scan_len > MAX_SCAN)
        scan_len = MAX_SCAN;

    char window[MAX_SCAN] = {};
    bpf_probe_read_user(window, scan_len, buf + 9);

#pragma unroll
    for (int i = 0; i < MAX_SCAN - TARGET_LEN; i++) {
        if (i >= scan_len - TARGET_LEN)
            break;

        int matched = 1;

#pragma unroll
        for (int j = 0; j < TARGET_LEN; j++) {
            if (window[i + j] != target[j]) {
                matched = 0;
                break;
            }
        }

        if (matched) {
            bpf_probe_write_user(buf + 9 + i, inject, TARGET_LEN);
            bpf_trace_printk("overwrite user-agent value offset=%d\\n", i);
            break;
        }
    }

    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", type=int, required=True)
parser.add_argument(
    "--libssl",
    default="/usr/lib/x86_64-linux-gnu/libssl.so.3"
)

args = parser.parse_args()

b = BPF(text=BPF_SRC)

b.attach_uprobe(
    name=args.libssl,
    sym="SSL_write",
    fn_name="trace_ssl_write",
    pid=args.pid
)

print(f"[+] attached SSL_write uprobe on pid={args.pid}")
print(f"[+] libssl = {args.libssl}")
print("[+] target: curlsig0 -> sig00001")
print("[+] press Ctrl-C to stop")

try:
    while True:
        (_, _, _, _, _, msg) = b.trace_fields()
        print(msg.decode(errors="ignore"))
except KeyboardInterrupt:
    print("\n[+] detached")