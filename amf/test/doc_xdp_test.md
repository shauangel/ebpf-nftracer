# amf/test/test_xdp.c — testing `../amf_xdp.c`

`test_xdp.c` is a **loader** for `../amf_xdp.c`: it compiles it into a real
BPF object (`amf_xdp.o`), loads it into the kernel with libbpf, and drives
it with the kernel's `BPF_PROG_TEST_RUN` facility against hand-built raw
packets — no veth pair, no network namespace, no real NIC. This is the same
technique the kernel's own BPF selftests use to unit-test XDP programs in
isolation. See [`map_test.md`](map_test.md) for the `sm_nodes`/`sm_edges`
map tests this one builds on.

**What's being tested:** `amf_xdp_enforce()` must be able to tell an
SCTP/NGAP packet (the only traffic it's meant to inspect — see
`../amf_xdp.c`'s file header) apart from ordinary HTTP-over-TCP traffic,
which must sail through completely untouched ("fail-open by design", per
that same header comment).

## Requirements

Everything [`map_test.md`](map_test.md#requirements) requires, plus:

- **clang**, to build `amf_xdp.o` (`amf/test/Makefile` runs
  `clang -target bpf ...`, the same command `../README.md`'s "Building &
  Running" section documents for hand-compiling `amf_xdp.c`).
- **A libbpf recent enough to have `bpf_prog_test_run_opts()`** (the
  modern, non-deprecated test-run entry point; same rough libbpf-version
  baseline the rest of this suite already assumes for `bpf_map_create()`).

Build with:

```sh
cd amf/test
make test_xdp     # also builds amf_xdp.o as a side effect (see Makefile)
sudo ./test_xdp
```

`amf_xdp.o` is built **into `amf/test/`**, not `../` — nothing is added to
the parent `amf/` directory by this test suite.

## Why `BPF_PROG_TEST_RUN` instead of a real veth + `ip link set xdp`

`../amf_xdp.c`'s own documented attach procedure is:

```sh
sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
```

That needs a specific veth already wired up to a running AMF container's
N2 interface — not something a test suite can spin up portably, and not
something that gives you fine control over exact packet bytes anyway.
`BPF_PROG_TEST_RUN` (exposed by libbpf as `bpf_prog_test_run_opts()`) sidesteps
all of that: it hands a raw byte buffer straight to the *loaded* program as
`ctx->data`/`ctx->data_end`, runs it for real in the kernel, and reports
back the program's actual return value (`XDP_PASS`, `XDP_DROP`, ...). The
program has no way to tell this apart from a packet that arrived on a real
NIC — it only ever looks at `ctx->data`/`ctx->data_end`, both of which
`BPF_PROG_TEST_RUN` populates from the buffer you hand it.

## Why the maps need to be repopulated here too

`../amf_xdp.c` `#include`s `../sm_map.c`, so the compiled `amf_xdp.o`
declares the same pinned `sm_nodes`/`sm_edges` maps `map_test.md`'s tests
exercise directly. Loading `amf_xdp.o` will create+pin them (empty) if this
is the first BPF object on the box to ever touch them — exactly the
"loads first, creates+pins them EMPTY" scenario `../amf_xdp.c`'s own header
comment warns about. `test_xdp.c`'s `main()` deals with this the same way
`amf_loader.c` does in production: after loading, it calls
`fx_populate_nodes()`/`fx_populate_edges()` (from `fixtures.h`, the real
29-node/52-edge table) on `amf_xdp.o`'s own `sm_nodes`/`sm_edges` map fds,
**unconditionally** — this is an idempotent upsert (`BPF_ANY`), so it's
correct and harmless whether it just created those maps empty or they
already existed (e.g. a real `amf_loader` is running on the same box).

## Code walkthrough

### Mirrored constants/structs

`../amf_xdp.c` defines several things privately — an enum for its stats
array indices, a `struct ue_val` for its per-UE map, plus assorted
`#define`s (`ETH_P_IP`, `IPPROTO_SCTP`, ...) — none of which are exposed
through `../sm_map.h` (the only header both files share). Since
`amf_xdp.c` is only ever *loaded as a compiled `.o`* here, never
`#include`d as source, `test_xdp.c` keeps its own byte-identical copies:

```c
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };

struct ue_val {
    char     state[SM_NAME_MAX];   /* SM_NAME_MAX comes from sm_map.h -- real, shared */
    uint64_t last_seen_ns;
};
```

This is the same convention `fixtures.h` already uses for mirroring
`../amf_comm.c`'s FSM table — keep these in sync with `../amf_xdp.c` by
inspection if it ever changes.

### The packet-builder structs

`test_xdp.c` needs to write real Ethernet/IPv4/SCTP/TCP header bytes from
plain userspace C, which rules out `../amf_xdp.c`'s own approach
(`vmlinux.h`'s BTF-derived kernel structs, only usable in a BPF-target
compilation). It also deliberately avoids the normal userspace fix
(`<linux/if_ether.h>`/`<linux/ip.h>`/`<netinet/tcp.h>`), because mixing
`linux/*.h` and `netinet/*.h` network headers in one translation unit is a
well-known source of duplicate-definition build errors on Linux.

Instead, `test_xdp.c` defines its own minimal, `__attribute__((packed))`
structs (`test_ethhdr`, `test_iphdr`, `test_sctphdr`,
`test_sctp_data_chunk`, `test_tcphdr`). Two of them —
`test_sctphdr`/`test_sctp_data_chunk` — are byte-for-byte mirrors of
`../amf_xdp.c`'s own `struct sctphdr_simple`/`struct sctp_data_chunk`,
since those are exactly what `amf_xdp_enforce()` parses the wire bytes as.

The trickiest part of hand-rolling `test_iphdr`/`test_tcphdr` is normally
the bitfields (IPv4's 4-bit version + 4-bit IHL packed into one byte; TCP's
4-bit data-offset). Rather than reproduce the host's own
byte-order-dependent bitfield packing, both are written as a single
already-packed literal:

- `0x45` for IPv4 = version 4 (high nibble) + IHL 5/20-byte-header (low
  nibble) — this is the literal byte RFC 791 puts on the wire, true on any
  host regardless of how *that host's* C compiler would pack an equivalent
  bitfield.
- `0x50` for TCP = data offset 5/20-byte-header (high nibble) + reserved
  bits 0 (low nibble), same reasoning, RFC 793.

This sidesteps bitfield-order ambiguity entirely instead of trying to get
it right.

### `build_sctp_ngap_initial_ue_message()`

Builds, byte by byte, a complete Ethernet → IPv4 → SCTP → single DATA chunk
frame whose payload's first two bytes are `procedureCode = 15`
(`id-InitialUEMessage`, 3GPP TS 38.413) — i.e. exactly what a real gNB's
very first NGAP message to the AMF looks like at the byte level
`amf_xdp_enforce()` actually reads:

1. `struct test_ethhdr` with `ethertype = htons(ETH_P_IP)` — the first
   thing `amf_xdp_enforce()` checks (`eth->h_proto != bpf_htons(ETH_P_IP)`
   → early `XDP_PASS` otherwise).
2. `struct test_iphdr` with `protocol = IPPROTO_SCTP` (132) — the second
   check, and the one this whole test suite is built around: change this
   one field and every other check downstream stops applying.
3. `struct test_sctphdr` — ports are filled in for realism (NGAP's IANA
   port 38412) but `amf_xdp_enforce()` never actually reads them.
4. `struct test_sctp_data_chunk` with `type = SCTP_DATA` (0) and
   `ppid = htonl(SCTP_PPID_NGAP)` (60) — both checked
   (`chunk->type != SCTP_DATA` / `bpf_ntohl(chunk->ppid) != SCTP_PPID_NGAP`
   → early `XDP_PASS` otherwise).
5. 16 raw bytes standing in for the start of the NGAP PDU: the first two
   are `{0x00, 15}` (procedureCode 15, big-endian, matching
   `amf_xdp.c`'s raw `(b0 << 8) | b1` read); the rest are padding just to
   satisfy the `ngap + 16 > data_end` bounds check — their content is
   never inspected.

It writes the packet's source IP out through an output parameter, since
that IP becomes `amf_xdp.c`'s `src_ip` — the key into both
`amf_xdp_rate_map` and `ue_state_map` — so the test can look the resulting
state up afterward.

### `build_http_get_request()`

Builds an ordinary Ethernet → IPv4 → TCP frame carrying a literal
`GET / HTTP/1.1` request — real, readable HTTP bytes, so a human looking at
a packet capture would immediately recognize it as web traffic, not just
"some non-SCTP protocol number". The one field that matters functionally
is `iph.protocol = IPPROTO_TCP` (6): `amf_xdp_enforce()`'s very first
protocol check (`iph->protocol != IPPROTO_SCTP`) fails immediately, and it
never parses a single byte of the TCP header or HTTP text that follows —
they're there for realism/readability, not because the program under test
looks at them.

### `run_xdp_prog()`

Thin wrapper around `bpf_prog_test_run_opts()`:

```c
struct bpf_test_run_opts opts = {0};
opts.sz            = sizeof(opts);
opts.data_in       = pkt;
opts.data_size_in  = (uint32_t)len;
opts.data_out      = pkt_out;       /* 4096-byte scratch buffer */
opts.data_size_out = sizeof(pkt_out);
opts.repeat        = 1;

bpf_prog_test_run_opts(prog_fd, &opts);
return opts.retval;   /* the program's real XDP_PASS/XDP_DROP/... return value */
```

`data_out`/`data_size_out` are supplied even though `amf_xdp_enforce()`
never mutates a packet (no `bpf_xdp_adjust_head()` etc.), because some
kernel versions expect a real output buffer whenever `data_in` is set.
`ctx_in` is deliberately left `NULL` — that tells the kernel to derive the
`xdp_md`'s `data`/`data_end` purely from `data_in`/`data_size_in`, which is
all `amf_xdp_enforce()`'s parsing logic (`ctx->data`/`ctx->data_end` only,
no `ingress_ifindex`/`rx_queue_index` checks) needs.

### The three tests

Program/map fds are loaded once in `main()` and shared by every test
through file-scope statics (`g_prog_fd`/`g_stats_fd`/`g_ue_fd`), since all
three tests exercise the *same* loaded `amf_xdp_enforce()` instance and its
*same* maps — the HTTP test's whole point is checking that the stats map
`test_sctp_ngap_packet_is_categorized()` just wrote to is untouched by the
next packet.

- **`test_stats_start_at_zero`** — sanity check. `amf_xdp_stats`/
  `ue_state_map` are plain (unpinned) maps, freshly created by this
  process's own `bpf_object__load()` call, never shared with a prior run,
  so every stat must read back as exactly `0`.

- **`test_sctp_ngap_packet_is_categorized`** — sends the SCTP/NGAP
  `InitialUEMessage` built above and checks, not just the return code, but
  every observable side effect a real categorized packet should have:
  - `retval == XDP_PASS` (a single packet is nowhere near the 50/s rate
    limit).
  - `amf_xdp_stats[STAT_PASS] == 1` — it went all the way through
    `bump_stat(STAT_PASS)` at the bottom of the function.
  - `amf_xdp_stats[STAT_STATE_INVALID] == 0` — and specifically as a
    **clean FSM hit**, not a mismatch that merely didn't get dropped:
    `fixtures.h` really does contain the
    `UE/gNB --InitialUEMessage--> REG_RECEIVED` edge `amf_xdp_enforce()`
    looks up for a source it's never seen before (`from_state` defaults to
    `"UE/gNB"`).
  - `ue_state_map[src_ip].state == "REG_RECEIVED"` — read back through the
    locally-mirrored `struct ue_val`, proving `ue_state_set()` really ran.

- **`test_http_packet_is_not_categorized`** — sends the HTTP/TCP packet and
  checks that it changed *nothing*:
  - `retval == XDP_PASS` — but via the fail-open early-return path, not the
    categorized-and-passed path (indistinguishable by return code alone,
    which is exactly why the next two checks matter).
  - `amf_xdp_stats[STAT_PASS]` is still exactly `1` — the same value the
    previous test left it at, not `2`. This is the crux of "distinguish
    SCTP from HTTP": it proves this packet never reached `bump_stat()` at
    all, not merely that some other counter absorbed it.
  - `bpf_map_lookup_elem()` on `ue_state_map` for the HTTP packet's source
    IP returns `-ENOENT` — no entry was ever created, because
    `amf_xdp_enforce()` returned before it ever computed an FSM state for
    this source.

### `main()`

Mirrors the real `amf_loader` → `amf_xdp.o` boot order described in
`../README.md`'s "Building & Running" section, just in one process instead
of two:

1. `require_root()` — loading a `BPF_PROG_TYPE_XDP` program and issuing
   `BPF_PROG_TEST_RUN` both need real BPF privileges.
2. `bpf_object__open_file("amf_xdp.o", NULL)` + `bpf_object__load(obj)` —
   parse and load the object; this is also the point at which
   `sm_nodes`/`sm_edges` get created+pinned (or reused) per `../sm_map.c`'s
   `LIBBPF_PIN_BY_NAME` declarations.
3. Look up the program (`amf_xdp_enforce`) and all four maps it declares
   (`sm_nodes`, `sm_edges`, `amf_xdp_stats`, `ue_state_map`) by name.
4. `fx_populate_nodes()`/`fx_populate_edges()` — unconditionally
   (re)populate the real FSM table, exactly like `amf_loader.c`'s
   `sm_map_populate()` does every time it starts.
5. `RUN_TEST()` the three tests above, in order (each depends on the stats
   state the previous one left behind).
6. `bpf_object__close(obj)` — closes the program fd and every map fd this
   object owns in one call.

## Notes / things this test deliberately does NOT cover

- **The rate limiter** (`amf_xdp_rate_map`, `RATE_MAX_PER_WIN = 50`) — each
  test here sends exactly one packet per scenario, nowhere near the
  threshold. Exercising the actual `XDP_DROP` flood path would need ~51
  `InitialUEMessage` packets from the same source in one `repeat`d
  `bpf_prog_test_run_opts()` call (`opts.repeat` can do this in one
  syscall) — a reasonable next test to add, not attempted here since it
  wasn't the ask.
- **FSM-mismatch flagging** (`STAT_STATE_INVALID` actually going non-zero)
  — would need a source already mid-registration (an existing
  `ue_state_map` entry) receiving an out-of-spec label next, similar in
  spirit to `sm_use_case.c`'s T5 attack step but driven through the XDP
  program instead of a direct map lookup. Out of scope for "distinguish
  SCTP from HTTP" specifically.
- **A real veth attach** (`sudo ip link set dev ... xdp obj amf_xdp.o sec
  xdp`) — intentionally not exercised; see "Why `BPF_PROG_TEST_RUN`..."
  above.
