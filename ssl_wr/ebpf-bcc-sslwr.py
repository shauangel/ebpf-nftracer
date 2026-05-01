#!/usr/bin/env python3
from bcc import BPF
import argparse
import ctypes
import time

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>

#define SIG_LEN 32
#define FIXED_OFF 73

int trace_ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len < 9 + FIXED_OFF + SIG_LEN)
        return 0;

    unsigned char hdr[9];
    bpf_probe_read_user(hdr, sizeof(hdr), buf);

    unsigned char frame_type = hdr[3];

    // HTTP/2 HEADERS frame
    if (frame_type != 0x01)
        return 0;

    char inject[SIG_LEN] = "ebpf-injected-signature-000001";

    // payload starts at buf + 9
    bpf_probe_write_user(buf + 9 + FIXED_OFF, inject, SIG_LEN);

    bpf_trace_printk("fixed inject ok\\n");
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