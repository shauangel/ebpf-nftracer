# amf/test/test_xdp.c — auto-attach loader + detach watchdog for `../xdp_ngap.c`

`test_xdp.c` is a small, long-running **loader + watchdog**, not an
automated pass/fail test: it loads the real, compiled `xdp_ngap.bpf.o`,
attaches its single program (`xdp_prog`) to a real interface — waiting for
that interface to exist rather than requiring it up front — and then polls
once every `POLL_INTERVAL_SEC` seconds for as long as it's the program
actually attached there, until you hit Ctrl+C. See
[`map_test.md`](map_test.md) for the `sm_nodes`/`sm_edges` map tests this
suite otherwise consists of; unlike those, this file never touches
`sm_nodes`/`sm_edges` at all — `../xdp_ngap.c` (the "legacy, superseded"
passive version — see `../README.md`) declares no FSM maps of its own,
just one `SEC("xdp")` program that parses Ethernet/IP and, per-packet,
either SCTP/NGAP or TCP/HTTP, reporting whichever it recognizes and always
returning `XDP_PASS`.

**What it demonstrates:** that `xdp_prog` can be attached without any
manual `ip link` invocation, and — the harder property to see any other
way — that if it ever stops being the program attached to the interface
(someone runs `ip link set dev <iface> xdp off`, a different program
replaces it, or the interface itself is torn down/recreated), that fact
gets **noticed and reported**, not silently missed.

Each NGAP DATA chunk *and* each recognized HTTP/1.x request or response
line `xdp_prog` sees is also reported **directly in this process's own
output**, not just via `bpf_printk()`/`trace_pipe`: `../xdp_ngap.c`
submits a `struct xdp_event` (see `../xdp_ngap_event.h`) through its own
`BPF_MAP_TYPE_RINGBUF` map (`events`) for either kind, tagged by a `type`
field, and `test_xdp.c` drains that ringbuf itself and prints each record
as it arrives. That's the one BPF-side change this loader depends on:
`xdp_ngap.c` used to be `bpf_printk()`-only (and SCTP/NGAP-only), visible
solely via `sudo cat /sys/kernel/debug/tracing/trace_pipe`; it isn't
anymore.

## Why a watchdog instead of an automated test

`xdp_prog` has no maps and no meaningful return value to assert on (it
always returns `XDP_PASS` — see `../xdp_ngap.c`), so there's nothing for a
`BPF_PROG_TEST_RUN`-style assertion to check beyond "did it load," which
`bpf_object__load()` failing outright already covers. What actually matters
for a program meant to run unattended is whether it *stays* attached — and
that's a property polling has to watch for over time, not something a
single load-and-exit test can assert once and be done with.

## Requirements

Everything [`map_test.md`](map_test.md#requirements) requires, plus:

- **clang**, to build `xdp_ngap.bpf.o` (see the Makefile's `xdp_ngap.bpf.o`
  rule — the same `clang -target bpf ...` command `../README.md`'s
  "Building & Running" section documents for hand-compiling `xdp_ngap.c`'s
  sibling `amf_xdp.c`).
- **libbpf with `bpf_xdp_attach()`/`bpf_xdp_detach()`/`bpf_xdp_query_id()`**
  (libbpf >= 0.6 — these replaced the older, deprecated
  `bpf_set_link_xdp_fd()`) **and `ring_buffer__new()`/`__poll()`/`__free()`**
  (the same ringbuf API `../amf_loader.c` already uses for its own
  `events` map).
- Root, same as everything else in this directory — attaching an XDP
  program additionally needs `CAP_NET_ADMIN` on top of the `CAP_BPF` the
  rest of this suite requires.

**Not** required, unlike the map tests: bpffs mounted at `/sys/fs/bpf` —
`test_xdp` never pins anything.

The target interface does **not** need to already exist when you start
`test_xdp` — see "attach automatically" below. Default is `veth5538fab`
(`../amf_xdp.c`'s own documented attach target, reused here since
`xdp_ngap.c` attaches to the same N2 veth — see `../README.md`'s "Building
& Running"), overridable as `argv[1]`.

## Usage

```sh
cd amf/test
make test_xdp                 # also builds xdp_ngap.bpf.o (see Makefile)
sudo ./test_xdp                # attaches to veth5538fab
# or:
sudo ./test_xdp my-other-veth  # attaches to a different interface
```

`xdp_ngap.bpf.o` is built **into `amf/test/`**, not `../` — nothing is
added to the parent `amf/` directory.

`test_xdp` is deliberately **not** part of `make test`'s automated run loop
(it never exits on its own) — see `WATCH_BINS` vs. `BINS` in the Makefile.
Build it with plain `make` (which builds everything) or `make test_xdp`
specifically; run it by hand.

While it's running, any real SCTP association carrying an NGAP DATA chunk,
or any plain TCP connection carrying a recognizable HTTP/1.x request or
response line, across the interface prints a line here directly, e.g.:

```
[21:42:07] NGAP  10.0.0.1:38412 -> 10.0.0.2:38412  len=42  procedureCode=15  criticality=0
[21:42:09] HTTP  10.0.0.3:52344 -> 10.0.0.4:80     GET
[21:42:09] HTTP  10.0.0.4:80    -> 10.0.0.3:52344  HTTP
```

(`procedureCode`/`criticality` are the raw NGAP PDU bytes `xdp_prog` reads
off the wire, unchanged from what it used to `bpf_printk()` — see 3GPP TS
38.413's NGAP-PDU-Descriptions ASN.1 module for what each `procedureCode`
value maps to. `method` is one of `GET`/`POST`/`PUT`/`HEAD`/`DELETE`/
`PATCH`/`OPTIONS` for a request, or literally `HTTP` for a response status
line — this loader doesn't decode either protocol any further than
`xdp_ngap.c` already does.)

While it's running, in another shell on the same box, try breaking it on
purpose and watch it notice:

```sh
sudo ip link set dev veth5538fab xdp off      # -> "xdp_prog was DETACHED" alert, then re-attaches itself
sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp   # -> "xdp_prog ... was REPLACED" alert (won't fight over it)
sudo ip link del veth5538fab                   # -> "interface ... disappeared" alert, then waits for it to come back
```

Ctrl+C detaches the program (if it's still the one attached) and exits
cleanly.

## Code walkthrough

### `DEFAULT_IFACE` / `XDP_OBJ_PATH` / `XDP_PROG_NAME` / `XDP_EVENTS_MAP` / `POLL_INTERVAL_SEC`

The knobs the rest of the file is built around: `"veth5538fab"`,
`"xdp_ngap.bpf.o"` (this directory's build output, not `../xdp_ngap.c`
directly — a BPF object has to be compiled first), `"xdp_prog"` (must
match `xdp_ngap.c`'s `SEC("xdp") int xdp_prog(...)` by name exactly, since
it's looked up post-load via `bpf_object__find_program_by_name()`),
`"events"` (must match `xdp_ngap.c`'s `BPF_MAP_TYPE_RINGBUF` map name,
looked up via `bpf_object__find_map_by_name()`), and `2` seconds as the
upper bound between watchdog checks (see `handle_xdp_event()` below for
why it's an upper bound, not a fixed interval).

### `struct xdp_event` / `../xdp_ngap_event.h`

The record type both sides of the ringbuf agree on — `#include`'d by both
`../xdp_ngap.c` (BPF side, fills and submits it) and this file (userspace
side, reads it back), the same sharing pattern `../sm_map.h` uses for
`sm_nodes`/`sm_edges`. One struct covers both event kinds, discriminated by
a `type` field (`XDP_EVT_NGAP` / `XDP_EVT_HTTP`) — same "tag + per-type
field usage documented in a comment, unused fields zeroed" convention
`../events.h`'s `struct event` already uses for the uprobe/tracepoint
tracer's several `EVT_*` kinds. NGAP fields (`chunk_len`,
`procedure_code`, `criticality`) and the HTTP field (`method`) are the
exact values `xdp_ngap.c` already had in hand — nothing decoded further
than it always was.

### `handle_xdp_event()`

`ring_buffer__new()`'s callback — libbpf invokes this once per
`struct xdp_event` `xdp_prog()` submits, whichever `handle_sctp()`/
`handle_tcp()` (see `../xdp_ngap.c`) produced it. Converts the two raw
`__u32` addresses back to dotted-quad with `inet_ntop()`, then switches on
`e->type` to print an `NGAP` or `HTTP` line with the fields that type
actually uses. This is the whole reason the ringbuf exists: previously the
only way to see the NGAP side of this was `sudo cat
/sys/kernel/debug/tracing/trace_pipe` catching `xdp_ngap.c`'s old
`bpf_printk()` calls (a separate, kernel-wide trace stream shared with
every other `bpf_printk()` on the system, and one that never covered HTTP
at all); now both kinds are this loader's own, attributable output.

### `stop` / `handle_signal()`

Same `volatile sig_atomic_t` + handler pattern `../amf_loader.c` uses for
`SIGINT`/`SIGTERM` — a signal only sets a flag; all the real cleanup
(detach, `bpf_object__close()`) happens back in `main()` once the flag is
observed, never inside the handler itself.

### `print_ts()` / `LOG()` / `ALERT()`

`print_ts()` is a wall-clock `HH:MM:SS` prefix (`localtime_r()`), unrelated
to `../amf_loader.c`'s `fmt_ts()` (which formats a boot-relative
`bpf_ktime_get_ns()` value out of a ring-buffer event — there is no such
event here, just this process's own clock). `LOG()`/`ALERT()` both prefix
a line with the timestamp and a trailing newline; `ALERT()` additionally
writes to `stderr` with a `*** ALERT:` marker, so a `2>` redirect or a log
scraper can separate "things changed, and it's bad" from routine status
lines without parsing message text.

### `wait_for_ifindex()`

Polls `if_nametoindex()` once a second until it succeeds (or `stop` is
set), printing a single `"waiting for interface ... to appear"` line the
first time it has to wait rather than one per second. This is what makes
attaching **automatic**: `main()` doesn't require `veth5538fab` to already
exist at startup — e.g. the AMF container that creates it hasn't launched
yet — it just waits. Reused later by the watchdog loop to wait for the
interface to come back if it disappears entirely.

### `attach_xdp()`

Tries `bpf_xdp_attach()` in **native/driver** mode first
(`XDP_FLAGS_DRV_MODE`), then falls back to **generic/SKB** mode
(`XDP_FLAGS_SKB_MODE`) if that fails — native mode isn't guaranteed on
every interface/driver, generic mode works everywhere a veth exists, at
some per-packet cost. Both attempts include
`XDP_FLAGS_UPDATE_IF_NOEXIST`, which makes the attach **fail** instead of
silently replacing whatever program is already attached, so `test_xdp` can
never accidentally steal the interface out from under a real
`amf_xdp.o`/`xdp_ngap.o` session already running there. On an `EBUSY`
failure (something's already attached), prints a specific hint pointing at
`ip link set dev <iface> xdp off` rather than a bare errno. Records which
mode won in `*flags_used`, since detaching later needs matching flags.

### `main()`

1. **Root check**, then resolve `ifname` from `argv[1]` or fall back to
   `DEFAULT_IFACE`, then install the signal handlers.
2. **Wait for the interface** (`wait_for_ifindex()`) — requirement 1,
   "attach automatically."
3. **Load `xdp_ngap.bpf.o`.** `bpf_object__open_file()` +
   `bpf_object__load()`, then `bpf_object__find_program_by_name()` for
   `"xdp_prog"` and `bpf_program__fd()` for its fd.
4. **Start draining `events`.** `bpf_object__find_map_by_name()` +
   `bpf_map__fd()` + `ring_buffer__new(fd, handle_xdp_event, NULL, NULL)`
   — done *before* attaching, so no event submitted the instant
   `attach_xdp()` succeeds can be missed.
5. **Attach** via `attach_xdp()`.
6. **Record `our_prog_id`** — `bpf_obj_get_info_by_fd(prog_fd, &info, ...)`
   → `info.id`. This is the baseline the watchdog loop compares against;
   it's this process's own program's kernel-assigned id, not anything
   read back off the interface.
7. **Watchdog loop** (requirement 2, "alert ... in any case") — every
   tick:
   - `ring_buffer__poll(rb, POLL_INTERVAL_SEC * 1000)` both drains
     `events` (firing `handle_xdp_event()` for anything queued, NGAP or
     HTTP) *and* provides the tick's timing — it blocks up to
     `POLL_INTERVAL_SEC` seconds but wakes early the moment an event
     arrives, so records print with real latency instead of batching up
     to once per tick. A negative return other than `-EINTR` (this
     process's own signal handler interrupting the wait) is a real libbpf
     error — alerted on, but not fatal to the watchdog loop.
   - `if_nametoindex(ifname) == 0` → the interface itself is gone. Alert
     once (state-gated, see below), then block in `wait_for_ifindex()`
     until it reappears, then re-attach with the *same* `prog_fd` (the
     loaded program itself was never affected by the interface vanishing,
     only its attachment was).
   - ifindex resolves but to a **different** number than before → the
     named interface was deleted and recreated between polls without ever
     being observed as absent. Treated the same as a detach: re-attach at
     the new ifindex.
   - `bpf_xdp_query_id(ifindex, 0, &cur_prog_id)` → `0` means nothing is
     attached anymore (`ip link ... xdp off` or equivalent) — alert, then
     re-attach automatically. A **different**, nonzero id means some other
     program replaced ours — alert, but deliberately does **not** try to
     reclaim the interface (silently overriding someone else's program
     would be just as surprising as the replacement itself). Matching
     `our_prog_id` and no prior alert state → stays completely silent,
     the same "don't print a heartbeat when nothing changed" convention
     `map_test.md`'s tests follow.
   - All of the above is gated by a 4-state `enum` (`STATE_ATTACHED` /
     `STATE_DETACHED` / `STATE_REPLACED` / `STATE_IFACE_GONE`) so each
     alert prints exactly once per state **transition**, with a matching
     "attached again" line when it recovers, instead of repeating every
     `POLL_INTERVAL_SEC` for as long as the underlying problem persists.
8. **On Ctrl+C:** logs the shutdown, calls `bpf_xdp_detach()` if the last
   known state was `STATE_ATTACHED`/`STATE_REPLACED` (nothing to detach if
   the interface itself is gone), then `ring_buffer__free(rb)` and
   `bpf_object__close(obj)`.

## Notes / things this watchdog deliberately does NOT do

- **No assertions, no pass/fail exit code.** Like the original design this
  file replaced, this is an operational tool, not a `make test` check —
  see `WATCH_BINS` in the Makefile.
- **Doesn't decode NGAP or HTTP any further than `xdp_ngap.c` already
  does.** `handle_xdp_event()` prints the raw `procedureCode`/
  `criticality` bytes or the raw 3-4 byte method-prefix match `xdp_prog()`
  produced, same shallow depth its old `bpf_printk()` call had for NGAP —
  no ASN.1 PER decode, no procedure-code-to-name lookup, no HTTP header/
  URL/body parsing beyond "does the first 4 bytes of this TCP payload look
  like a request or status line." `xdp_prog()` itself no longer calls
  `bpf_printk()` (see `../xdp_ngap_event.h`'s file header) — the
  unrelated, already-unused `dump_bytes()` helper still has one in its
  body, but nothing calls that function, so there's nothing left on
  `trace_pipe` for this program in practice.
- **HTTP detection is content-based, not port-based.** `handle_tcp()` (in
  `../xdp_ngap.c`) never checks `tcp->source`/`tcp->dest` against port 80
  or any other specific port — it only looks at whether the TCP payload's
  first few bytes match a known HTTP/1.x method or the `"HTTP/"` response
  prefix, the same "identify by wire content, not by port" approach
  `handle_sctp()` already used for NGAP (via the SCTP DATA chunk's PPID).
  This means it'll also flag HTTP running on a non-standard port, and
  correspondingly won't flag non-HTTP traffic that merely happens to use
  port 80.
- **Doesn't reclaim an interface a different program took over.** See
  `STATE_REPLACED` above — alerts, but leaves the other program in place
  rather than fighting over it every poll.
- **Polls rather than subscribing to netlink link events.** There's no
  "XDP program detached" netlink notification to listen for instead;
  `POLL_INTERVAL_SEC`-interval polling via `bpf_xdp_query_id()` is the
  same approach real XDP loaders (e.g. `xdp-loader`) use for this.
