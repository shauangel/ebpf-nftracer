# amf/test/test_xdp.c — live monitor for `../amf_xdp.c`

`test_xdp.c` is a small **live monitor**, not an automated pass/fail test:
it loads the real, compiled `amf_xdp.o`, attaches `amf_xdp_enforce()` as an
actual XDP program on a real interface, and once a second prints
`amf_xdp_stats` (`PASS`/`DROP`/`STATE_INVALID`) and every entry in
`ue_state_map`, until you hit Ctrl+C. See [`doc_map_test.md`](doc_map_test.md)
for the `sm_nodes`/`sm_edges` map tests this builds on.

Alongside that, it also runs its own **independent, userspace SCTP/NGAP
sniffer** — the exact same recognition logic `../xdp_ngap.c`'s
already-working `xdp_prog()` uses (same constants, same Ethernet → IPv4 →
SCTP → DATA-chunk → NGAP-procedureCode walk), just run over an
`AF_PACKET`/`SOCK_RAW` capture in this process instead of as a second
attached BPF program. `../xdp_ngap.c` itself is never modified or built —
its logic is simply copied into `parse_and_print_sctp_ngap()` below, adapted
to read a plain userspace buffer instead of `ctx->data`/`ctx->data_end`.

**What it demonstrates:** `amf_xdp_enforce()` must tell an SCTP/NGAP packet
(the only traffic it's meant to inspect — see `../amf_xdp.c`'s file header)
apart from ordinary HTTP traffic, which must sail through completely
untouched ("fail-open by design"). Attach it to an interface, send it real
HTTP traffic and watch nothing move, then send it a real SCTP/NGAP
`InitialUEMessage` and watch `amf_xdp_stats`/`ue_state_map` react.

## Why the raw sniffer exists

If `amf_xdp_stats` never moves even though you're confident real SCTP/NGAP
traffic is crossing the interface, that's ambiguous on its own — is the
traffic not arriving/parsing at all, or is `amf_xdp.c`'s categorization
(`ngap_procedure_label()`) or FSM lookup specifically the problem? The raw
sniffer answers that directly, with **zero dependency on any BPF/XDP
mechanism**: if lines prefixed `[raw-sniff]` show up, the packets really are
arriving and are structurally valid SCTP/NGAP (right protocol, right PPID,
right chunk type) — so the bug is further up `amf_xdp.c`'s own pipeline,
not in the packets themselves or the parsing constants (which are shared,
byte-for-byte, between `../xdp_ngap.c` and `../amf_xdp.c`). If `[raw-sniff]`
shows nothing either, the packets aren't reaching this interface as
recognizable SCTP/NGAP at all (wrong interface, wrong direction, wrong PPID,
not actually SCTP, etc.) — a problem with the traffic/setup, not with
`amf_xdp.c`'s code.

## Why a monitor instead of an automated test

An earlier version of this file fed `amf_xdp_enforce()` synthetic packets
through the kernel's `BPF_PROG_TEST_RUN` facility and asserted on the result
— useful for point-checking the parser in isolation, deterministic,
CI-friendly. But it can't show the thing that actually matters day to day:
does the program correctly categorize traffic *as it actually arrives on the
wire*, on a *real* interface, possibly interleaved with everything else a
real veth carries. This version trades determinism for that — it's a tool
you run while generating real traffic and watch, not something with a
pass/fail exit code.

## Requirements

Everything [`doc_map_test.md`](doc_map_test.md#requirements) requires, plus:

- **clang**, to build `amf_xdp.o` (see the Makefile's `amf_xdp.o` rule —
  the same `clang -target bpf ...` command `../README.md`'s "Building &
  Running" section documents for hand-compiling `amf_xdp.c`).
- **libbpf with `bpf_xdp_attach()`/`bpf_xdp_detach()`/`bpf_xdp_query()`**
  (libbpf >= 0.6 — these replaced the older, deprecated
  `bpf_set_link_xdp_fd()`/`bpf_get_link_xdp_id()`).
- **debugfs or tracefs mounted** (`/sys/kernel/debug/tracing/trace_pipe` or
  `/sys/kernel/tracing/trace_pipe`) to stream `bpf_printk()` output — standard
  on any modern distro; if neither is mounted, `test_xdp` prints one warning
  at startup and keeps running with everything else still working.
- **`CAP_NET_RAW`** for the `AF_PACKET`/`SOCK_RAW` sniffer socket — covered
  by root, same as everything else here. If it fails to open (permissions,
  sandboxing), `test_xdp` prints one warning and keeps running without it.
- **The target interface must already exist.** `test_xdp` attaches to it; it
  doesn't create it. Default is `veth5538fab` (`../amf_xdp.c`'s own
  documented attach target), overridable as `argv[1]`.
- Root, same as everything else in this directory (attaching an XDP program,
  opening a raw socket, and reading BPF maps all need real privileges).

## Usage

```sh
cd amf/test
make test_xdp                 # also builds amf_xdp.o (see Makefile)
sudo ./test_xdp                # attaches to veth5538fab
# or:
sudo ./test_xdp my-other-veth  # attaches to a different interface
```

`amf_xdp.o` is built **into `amf/test/`**, not `../` — nothing is added to
the parent `amf/` directory. `../xdp_ngap.c` is never built or referenced as
a file at all; only its recognition logic is copied into `test_xdp.c`
directly (see "Code walkthrough" below).

`test_xdp` is deliberately **not** part of `make test`'s automated run loop
(it never exits on its own) — see `MONITOR_BINS` vs. `TEST_BINS` in the
Makefile. Build it with plain `make` (which builds everything) or
`make test_xdp` specifically; run it by hand.

While it's running, in another shell on the same box:

```sh
# should NOT move amf_xdp_stats, create a ue_state_map entry, or print a
# [raw-sniff] line
curl --interface veth5538fab http://some-http-server/

# should move amf_xdp_stats, populate ue_state_map, AND print a
# [raw-sniff] line -- needs a real (or simulated) SCTP association
# carrying an NGAP InitialUEMessage across the same interface, e.g. from
# a real gNB/UE simulator pointed at it
```

Ctrl+C detaches the program from the interface and exits cleanly.

## Code walkthrough

### Mirrored constants/structs (from `../amf_xdp.c`)

`../amf_xdp.c` defines its stats-array indices and its per-UE value struct
privately — neither is exposed through `../sm_map.h` (the only header both
files share). Since `amf_xdp.c` is only ever *loaded as a compiled `.o`*
here, never `#include`d as source, `test_xdp.c` keeps byte-identical copies:

```c
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };

struct ue_val {
    char     state[SM_NAME_MAX];   /* SM_NAME_MAX comes from sm_map.h -- real, shared */
    uint64_t last_seen_ns;
};
```

Same convention `fixtures.h` uses for mirroring `../amf_comm.c`'s FSM table
— keep these in sync with `../amf_xdp.c` by inspection if it ever changes.

### Mirrored constants/structs (from `../xdp_ngap.c`) + `parse_and_print_sctp_ngap()`

```c
#define RAW_ETH_P_IP       0x0800 /* == xdp_ngap.c's ETH_P_IP */
#define RAW_IPPROTO_SCTP   132    /* == xdp_ngap.c's IPPROTO_SCTP */
#define RAW_SCTP_PPID_NGAP 60     /* == xdp_ngap.c's SCTP_PPID_NGAP */
#define RAW_SCTP_DATA      0      /* == xdp_ngap.c's SCTP_DATA */
```

plus copies of its `struct sctphdr_simple`/`struct sctp_data_chunk`. These
are a direct copy of the constants/structs `../xdp_ngap.c` declares — kept
in sync with it by inspection, same convention as everything else mirrored
in this file. `parse_and_print_sctp_ngap()` then runs the exact same
validation chain `xdp_prog()` does, in the exact same order, just reading
from a plain `const unsigned char *buf` (a captured frame) instead of
`ctx->data`/`ctx->data_end`:

1. Ethernet header present, `ethertype == ETH_P_IP`.
2. IPv4 header present, `protocol == IPPROTO_SCTP`.
3. SCTP common header present (offset by the IP header's real length,
   `ihl * 4`, exactly like `xdp_ngap.c` — IP headers can be longer than 20
   bytes).
4. SCTP DATA chunk header present, `type == SCTP_DATA` and
   `ppid == SCTP_PPID_NGAP` (both network-byte-order fields, converted with
   `ntohl()`/`ntohs()` same as `xdp_ngap.c`'s `bpf_ntohl()`/`bpf_ntohs()`).
5. At least 2 more bytes present (the NGAP PDU's procedureCode).

Any failed check returns immediately without printing anything — the same
"fall through silently" behavior `xdp_prog()`'s early `return XDP_PASS;`s
have. Only a packet that passes every check gets printed, prefixed
`[raw-sniff]`, with the same fields `xdp_ngap.c`'s `bpf_printk()` line
reports (source/dest SCTP ports, chunk length, NGAP procedureCode).

### `open_raw_sniffer()` / `drain_raw_sniffer()`

```c
int fd = socket(AF_PACKET, SOCK_RAW, htons(RAW_ETH_P_ALL));
struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(RAW_ETH_P_ALL), .sll_ifindex = ifindex };
bind(fd, (struct sockaddr *)&sll, sizeof(sll));
```

A minimal, single-purpose packet capture — the same mechanism `tcpdump`
itself is built on, bound to exactly the interface being monitored, no BPF
filter attached (every frame is delivered to userspace and
`parse_and_print_sctp_ngap()` decides what to do with it). `O_NONBLOCK` so
`drain_raw_sniffer()` fits into the same once-a-second poll loop as
everything else, without a second thread. This capture is **completely
independent of `amf_xdp_enforce()`** — it runs whether or not the XDP
attachment is currently healthy, which is exactly what makes it useful as a
cross-check.

### `now_ns()` / `print_ts()`

`../amf_xdp.c` stamps `ue_val.last_seen_ns` with `bpf_ktime_get_ns()` —
nanoseconds since boot, i.e. `CLOCK_MONOTONIC`. `now_ns()` reads the same
clock from userspace so `dump_ue_state_map()`'s "last update N.Ns ago" is a
real, comparable age. `print_ts()` is unrelated — just a wall-clock
`HH:MM:SS` prefix for each printed line, same idea as `../amf_loader.c`'s
own `fmt_ts()` helper.

### `open_trace_pipe()` / `drain_trace_pipe()`

`bpf_printk()` (`../amf_xdp.c`'s existing FSM-mismatch and rate-limit-drop
traces) writes to one system-wide ring buffer exposed as
`/sys/kernel/debug/tracing/trace_pipe` (or `/sys/kernel/tracing/trace_pipe`
on a tracefs-only setup). Opened `O_NONBLOCK` for the same reason as the raw
sniffer socket. This is the same mechanism `sudo cat
/sys/kernel/debug/tracing/trace_pipe` uses — only one reader gets each line,
so running both at once is racy (fine for a debug tool).

### `dump_ue_state_map()`

Walks every entry in `ue_state_map` using the real kernel hash-map iteration
protocol — `bpf_map_get_next_key()` + `bpf_map_lookup_elem()` per key, the
same pattern `doc_map_test.md`'s `test_map_walk.c` uses for
`sm_nodes`/`sm_edges`. Only sources `amf_xdp_enforce()` actually categorized
as NGAP ever get an entry here — an HTTP client hammering the same interface
never will.

### `verify_attachment()`

Checks **two independent** ways the XDP attachment can go away, called once
per tick:

1. **The interface itself was destroyed (and maybe recreated).** An XDP
   attachment lives on the kernel `net_device`, not the interface *name* —
   if whatever owns this veth (commonly: a container that owns the other end
   restarting, e.g. an AMF/gNB container restarting as part of bringing up a
   UE simulator) tears it down, the attachment is destroyed right along with
   the old device. Detected by re-checking `if_nametoindex(ifname)` against
   the `ifindex` recorded at attach time:
   - Unchanged → nothing to do.
   - Different → device was replaced; `bpf_xdp_attach()` again onto the new
     ifindex.
   - Zero → interface is gone and hasn't come back; nothing left to detach,
     report and stop.

2. **The same device is still there, but something detached or replaced the
   program on it** — `ip link set dev X xdp off`, another attach call, a
   network-management daemon resetting link state — without touching the
   interface object itself. Check 1's ifindex comparison does **not** catch
   this: the device looks completely unchanged. Detecting it needs an actual
   query of which program (if any) is currently attached:
   ```c
   struct bpf_xdp_query_opts qopts = {0};
   qopts.sz = sizeof(qopts);
   bpf_xdp_query(ifindex, XDP_FLAGS_SKB_MODE, &qopts);
   uint32_t attached_id = qopts.skb_prog_id;
   ```
   compared against `our_prog_id` (this program's own id, read once at
   startup via `bpf_obj_get_info_by_fd()` on `prog_fd`). If they don't match
   — nothing attached, or something else's program — re-attach and report
   which case it was.

**Why both checks exist:** an earlier version of this file only implemented
check 1. In practice that turned out to be only *one* of the ways this
attachment disappears — the symptom after adding it changed from "detaches
immediately when another tool starts" to "detaches after a few minutes with
**no alert printed at all**." No alert means neither the ifindex-only check
nor a signal handler ever fired, which is exactly what you'd see if the
interface object itself was untouched (check 1: nothing to report) but
something else quietly cleared or replaced the XDP program on it while
`amf_xdp_stats` simply stopped moving because the program silently wasn't in
the datapath anymore. Check 2 exists specifically to make that case visible
and recoverable instead of silent.

If you instead see `test_xdp` itself print
`[*] Received signal N (...) -- detaching from ...`, that's a *third*,
different situation: something is actually sending this process
`SIGINT`/`SIGTERM` — not an interface or attachment problem at all. All
three cases now produce visibly different output.

### `main()`

Mirrors the real `amf_loader` → `amf_xdp.o` boot order `../README.md`
describes, in one process instead of two, then adds the attach/monitor/
detach loop that role doesn't otherwise need:

1. **Resolve the interface.** `if_nametoindex(ifname)` — fails loudly if the
   named interface doesn't exist.
2. **Load `amf_xdp.o`.** `bpf_object__open_file()` + `bpf_object__load()` —
   this is also the point at which `sm_nodes`/`sm_edges` get created+pinned
   (or reused) per `../sm_map.c`'s `LIBBPF_PIN_BY_NAME` declarations.
3. **Look up** the program (`amf_xdp_enforce`) and all four maps it declares
   by name.
4. **(Re)populate the FSM table**, unconditionally — an idempotent upsert,
   exactly like `amf_loader.c`'s `sm_map_populate()`.
5. **Read our own program's id** for `verify_attachment()` to compare
   against later.
6. **Open the trace pipe and the raw sniffer socket** (both non-fatal if
   they fail — everything else still works without them).
7. **Attach**, generic/SKB mode with `XDP_FLAGS_UPDATE_IF_NOEXIST` (fails
   rather than silently replacing something already attached).
8. **Install signal handlers** (`SIGINT`/`SIGTERM` → set
   `volatile sig_atomic_t g_stop`, recording which signal in
   `g_stop_signal`).
9. **Monitor loop**, once a second: drain the trace pipe, drain the raw
   sniffer, run `verify_attachment()`, then check `amf_xdp_stats` for
   changes and print a summary + `dump_ue_state_map()` if anything moved.
10. **On exit:** if the loop broke because the attachment was unrecoverably
    lost, there's nothing to detach — close everything and return non-zero.
    Otherwise, print which signal was received, `bpf_xdp_detach()`, close
    `obj` (closes every fd it owns).

## Notes / things this monitor deliberately does NOT do

- **No assertions, no exit code in the success case.** This is an
  observability tool, not a test — see "Why a monitor instead of an
  automated test" above.
- **Doesn't generate any traffic itself.** You need a real (or simulated)
  SCTP/NGAP source and some ordinary HTTP traffic on the same interface to
  see the two behaviors contrast.
- **The raw sniffer's line reassembly is best-effort.** `drain_raw_sniffer()`
  reads whatever's available per packet (`recv()` on `SOCK_RAW` always
  returns one full frame per call, so this isn't actually a risk in
  practice, unlike the trace-pipe reader's byte-stream reads).
- **Rate limiting and FSM-mismatch flagging** (`amf_xdp_rate_map`,
  `STAT_DROP`, `STAT_STATE_INVALID` actually going non-zero) will show up in
  the monitor output if real traffic triggers them, but nothing here drives
  those cases deliberately.
