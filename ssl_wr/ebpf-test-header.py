#!/usr/bin/env python3
from bcc import BPF
import ctypes
import argparse

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>

#define DUMP_LEN 64

struct data_t {
    u32 pid;
    u32 tid;
    int len;
    unsigned char first[DUMP_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_ssl_write(struct pt_regs *ctx) {
    struct data_t data = {};

    void *buf = (void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.tid = id;
    data.len = len;

    if (len > 0) {
        bpf_probe_read_user(data.first, sizeof(data.first), buf);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("len", ctypes.c_int),
        ("first", ctypes.c_ubyte * 64),
    ]

def print_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Data)).contents
    raw = bytes(e.first)

    print("=" * 80)
    print(f"pid={e.pid} tid={e.tid} len={e.len}")
    print(raw.hex(" "))

    # 嘗試找 HTTP/2 frame header
    for i in range(0, 32):
        if i + 9 > len(raw):
            break

        frame_len = (raw[i] << 16) | (raw[i + 1] << 8) | raw[i + 2]
        frame_type = raw[i + 3]
        flags = raw[i + 4]
        stream_id = int.from_bytes(raw[i + 5:i + 9], "big") & 0x7fffffff

        if frame_type in [0x00, 0x01, 0x04, 0x06, 0x08] and frame_len < 16384:
            print(
                f"possible h2 frame at offset={i}: "
                f"len={frame_len}, type=0x{frame_type:02x}, "
                f"flags=0x{flags:02x}, stream={stream_id}"
            )

def main():
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

    print(f"[+] attached SSL_write pid={args.pid}")
    print("[+] dumping first 64 bytes of SSL_write buffer")

    b["events"].open_perf_buffer(print_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()