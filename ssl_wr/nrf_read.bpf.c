// nrf_read.bpf.c
// uretprobe on net/http.readRequest — reads Method, URL.Path and headers
// from the returned *http.Request.
//
// Verify offsets for your Go version before attaching:
//   go tool nm -size ./nrf | grep -E "http\.Request|url\.URL"
//   objdump --dwarf=info ./nrf | grep -A 60 "DW_AT_name.*Request"

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ── net/http.Request field offsets (Go 1.21, linux/amd64) ────────────────────
//
//   Method     string   +0   (ptr 8B + len 8B = 16B)
//   URL        *url.URL +16  (pointer, 8B)
//   Proto      string   +24  (16B)
//   ProtoMajor int      +40  (8B)
//   ProtoMinor int      +48  (8B)
//   Header     Header   +56  (map[string][]string → *runtime.hmap, 8B)
//
#define REQ_METHOD_OFF   0
#define REQ_URL_OFF      16
#define REQ_HEADER_OFF   56

// ── url.URL field offsets (Go 1.21) ─────────────────────────────────────────
//
//   Scheme   string +0
//   Opaque   string +16
//   User     *…     +32
//   Host     string +40
//   Path     string +56   ← we want this
//
#define URL_PATH_OFF     56

// ── runtime.hmap offsets ─────────────────────────────────────────────────────
//
//   count       int            +0
//   flags       uint8          +8
//   B           uint8          +9   ← log2(num_buckets)
//   noverflow   uint16         +10
//   hash0       uint32         +12
//   buckets     unsafe.Pointer +16  ← pointer to bucket array
//
#define HMAP_B_OFF       9
#define HMAP_BUCKETS_OFF 16

// ── bmap (bucket) layout for map[string][]string ────────────────────────────
//
//   tophash  [8]uint8   +0    (8 bytes)
//   keys     [8]string  +8    (8 × 16 = 128 bytes)
//   values   [8][]string+136  (8 × 24 = 192 bytes)
//   overflow *bmap      +328
//
//   tophash[i] >= 5 (minTopHash) → slot i is occupied
//
#define BMAP_TOPHASH_OFF  0
#define BMAP_KEYS_OFF     8
#define BMAP_VALS_OFF     136
#define BMAP_KEY_SZ       16    // sizeof(string)       = {ptr,len}
#define BMAP_VAL_SZ       24    // sizeof([]string)     = {ptr,len,cap}
#define BMAP_SLOTS        8
#define TOPHASH_MIN_FULL  5


char LICENSE[] SEC("license") = "GPL";
// ── filter / event ───────────────────────────────────────────────────────────

// Set by loader to restrict to a single NRF pid (0 = all pids)
volatile const __u32 g_target_pid = 0;

struct header_event {
    __u32 pid;
    char  method[16];
    char  path[128];
    char  hdr_key[64];
    char  hdr_val[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);   // 4 MiB
} events SEC(".maps");

// ── probe ────────────────────────────────────────────────────────────────────

SEC("uretprobe/net_http_readRequest")
int probe_readrequest(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (g_target_pid && pid != g_target_pid)
        return 0;

    // Go amd64 register ABI: first return value lands in RAX
    __u64 req_ptr = PT_REGS_RC(ctx);
    if (!req_ptr) return 0;

    // ── Method ───────────────────────────────────────────────────────────────
    __u64 mptr = 0, mlen = 0;
    bpf_probe_read_user(&mptr, 8, (void *)(req_ptr + REQ_METHOD_OFF));
    bpf_probe_read_user(&mlen, 8, (void *)(req_ptr + REQ_METHOD_OFF + 8));

    // ── URL.Path ─────────────────────────────────────────────────────────────
    __u64 url_ptr = 0;
    bpf_probe_read_user(&url_ptr, 8, (void *)(req_ptr + REQ_URL_OFF));

    __u64 pptr = 0, plen = 0;
    if (url_ptr) {
        bpf_probe_read_user(&pptr, 8, (void *)(url_ptr + URL_PATH_OFF));
        bpf_probe_read_user(&plen, 8, (void *)(url_ptr + URL_PATH_OFF + 8));
    }

    // ── Header hmap ──────────────────────────────────────────────────────────
    __u64 hmap_ptr = 0;
    bpf_probe_read_user(&hmap_ptr, 8, (void *)(req_ptr + REQ_HEADER_OFF));
    if (!hmap_ptr) return 0;

    __u64 buckets_ptr = 0;
    bpf_probe_read_user(&buckets_ptr, 8, (void *)(hmap_ptr + HMAP_BUCKETS_OFF));
    if (!buckets_ptr) return 0;

    // ── Walk bucket 0 ────────────────────────────────────────────────────────
    // NRF requests carry <8 headers in practice so bucket 0 covers them all.
    // Extend to walk 2^B buckets if you need to capture larger header sets.
    __u8 tophash[BMAP_SLOTS] = {};
    bpf_probe_read_user(tophash, BMAP_SLOTS,
                        (void *)(buckets_ptr + BMAP_TOPHASH_OFF));

    // #pragma unroll forces the compiler to emit 8 independent code paths with
    // literal (constant) offsets — the BPF verifier requires this.
    #pragma unroll
    for (int s = 0; s < BMAP_SLOTS; s++) {
        if (tophash[s] < TOPHASH_MIN_FULL) continue;

        // Key: string {ptr, len}
        __u64 kptr = 0, klen = 0;
        bpf_probe_read_user(&kptr, 8,
            (void *)(buckets_ptr + BMAP_KEYS_OFF + s * BMAP_KEY_SZ));
        bpf_probe_read_user(&klen, 8,
            (void *)(buckets_ptr + BMAP_KEYS_OFF + s * BMAP_KEY_SZ + 8));
        if (!kptr || !klen) continue;

        // Value: []string slice {ptr, len, cap} — ptr points to a string array
        __u64 vslice_ptr = 0, vslice_len = 0;
        bpf_probe_read_user(&vslice_ptr, 8,
            (void *)(buckets_ptr + BMAP_VALS_OFF + s * BMAP_VAL_SZ));
        bpf_probe_read_user(&vslice_len, 8,
            (void *)(buckets_ptr + BMAP_VALS_OFF + s * BMAP_VAL_SZ + 8));
        if (!vslice_ptr || !vslice_len) continue;

        // First element of []string: string {ptr, len} at vslice_ptr + 0
        __u64 vptr = 0, vlen = 0;
        bpf_probe_read_user(&vptr, 8, (void *)vslice_ptr);
        bpf_probe_read_user(&vlen, 8, (void *)(vslice_ptr + 8));
        if (!vptr) continue;

        // Reserve ring buffer slot and fill it
        struct header_event *ev =
            bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (!ev) return 0;

        __builtin_memset(ev, 0, sizeof(*ev));
        ev->pid = pid;

        // bpf_probe_read_user_str always null-terminates the dst buffer
        if (mptr) bpf_probe_read_user_str(ev->method,  sizeof(ev->method),  (void *)mptr);
        if (pptr) bpf_probe_read_user_str(ev->path,    sizeof(ev->path),    (void *)pptr);
                  bpf_probe_read_user_str(ev->hdr_key, sizeof(ev->hdr_key), (void *)kptr);
                  bpf_probe_read_user_str(ev->hdr_val, sizeof(ev->hdr_val), (void *)vptr);

        bpf_ringbuf_submit(ev, 0);
    }

    return 0;
}

