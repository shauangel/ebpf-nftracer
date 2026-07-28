# amf/test/test_xdp.c — live monitor for `../amf_xdp.c`

`test_xdp.c` is a small **live monitor**, not an automated pass/fail test:
it loads the real, compiled `amf_xdp.o`, attaches `amf_xdp_enforce()` as an
actual XDP program on a real interface, and once a second prints
`amf_xdp_stats` (`PASS`/`DROP`/`STATE_INVALID`) and every entry in
`ue_state_map`, until you hit Ctrl+C. See [`doc_map_test.md`](doc_map_test.md)
for the `sm_nodes`/`sm_edges` map tests this builds on.

**What it demonstrates:** `amf_xdp_enforce()` must tell an SCTP/NGAP packet
(the only traffic it's meant to inspect — see `../amf_xdp.c`'s file header)
apart from ordinary HTTP traffic, which must sail through completely
untouched ("fail-open by design"). This monitor shows that live: attach it
to an interface, send it real HTTP traffic and watch nothing move, then
send it a real SCTP/NGAP `InitialUEMessage` and watch `amf_xdp_stats` and
`ue_state_map` react.

## Why a monitor instead of an automated test

An earlier version of this file fed `amf_xdp_enforce()` synthetic packets
through the kernel's `BPF_PROG_TEST_RUN` facility and asserted on the
result — useful for point-checking the parser in isolation, deterministic,
CI-friendly. But it can't show the thing that actually matters day to day:
does the program correctly categorize traffic *as it actually arrives on
the wire*, on a *real* interface, possibly interleaved with everything else
a real veth carries. This version trades determinism for that — it's a
tool you run while generating real traffic and watch, not something with a
pass/fail exit code.

## Requirements

Everything [`doc_map_test.md`](doc_map_test.md#requirements) requires, plus:

- **clang**, to build `amf_xdp.o` (see the Makefile's `amf_xdp.o` rule —
  the same `clang -target bpf ...` command `../README.md`'s "Building &
  Running" section documents for hand-compiling `amf_xdp.c`).
- **libbpf with `bpf_xdp_attach()`/`bpf_xdp_detach()`** (libbpf >= 0.6 —
  these replaced the older, deprecated `bpf_set_link_xdp_fd()`).
- **The target interface must already exist.** `test_xdp` attaches to it;
  it doesn't create it. Default is `veth5538fab` (`../amf_xdp.c`'s own
  documented attach target — see its file header and `../README.md`'s
  "Building & Running"), overridable as `argv[1]`.
- Root, same as everything else in this directory (attaching an XDP
  program and reading BPF maps both need real BPF/net privileges).

## Usage

```sh
cd amf/test
make test_xdp                 # also builds amf_xdp.o (see Makefile)
sudo ./test_xdp                # attaches to veth5538fab
# or:
sudo ./test_xdp my-other-veth  # attaches to a different interface
```

`amf_xdp.o` is built **into `amf/test/`**, not `../` — nothing is added to
the parent `amf/` directory.

`test_xdp` is deliberately **not** part of `make test`'s automated run loop
(it never exits on its own) — see `MONITOR_BINS` vs. `TEST_BINS` in the
Makefile. Build it with plain `make` (which builds everything) or
`make test_xdp` specifically; run it by hand.

While it's running, in another shell on the same box:

```sh
# should NOT move amf_xdp_stats or create a ue_state_map entry
curl --interface veth5538fab http://some-http-server/

# should move amf_xdp_stats and populate ue_state_map -- needs a real (or
# simulated) SCTP association carrying an NGAP InitialUEMessage across
# the same interface, e.g. from a real gNB/UE simulator pointed at it
```

Ctrl+C detaches the program from the interface and exits cleanly.

## Code walkthrough

### Mirrored constants/structs

`../amf_xdp.c` defines its stats-array indices and its per-UE value struct
privately — neither is exposed through `../sm_map.h` (the only header both
files share). Since `amf_xdp.c` is only ever *loaded as a compiled `.o`*
here, never `#include`d as source, `test_xdp.c` keeps byte-identical
copies:

```c
enum { STAT_PASS = 0, STAT_DROP = 1, STAT_STATE_INVALID = 2, STAT_MAX };

struct ue_val {
    char     state[SM_NAME_MAX];   /* SM_NAME_MAX comes from sm_map.h -- real, shared */
    uint64_t last_seen_ns;
};
```

Same convention `fixtures.h` uses for mirroring `../amf_comm.c`'s FSM
table — keep these in sync with `../amf_xdp.c` by inspection if it ever
changes.

### `now_ns()` / `print_ts()`

`../amf_xdp.c` stamps `ue_val.last_seen_ns` with `bpf_ktime_get_ns()` —
nanoseconds since boot, i.e. `CLOCK_MONOTONIC`. `now_ns()` reads the same
clock from userspace (`clock_gettime(CLOCK_MONOTONIC, ...)`) so
`dump_ue_state_map()`'s "last update N.Ns ago" is a real, comparable age,
not just a raw uninterpretable integer. `print_ts()` is unrelated —
just a wall-clock `HH:MM:SS` prefix for each printed line, same idea as
`../amf_loader.c`'s own `fmt_ts()` helper.

### `dump_ue_state_map()`

Walks every entry in `ue_state_map` using the real kernel hash-map
iteration protocol — `bpf_map_get_next_key()` + `bpf_map_lookup_elem()`
per key, the same pattern `doc_map_test.md`'s `test_map_walk.c` uses for
`sm_nodes`/`sm_edges` — and prints each as `<source IP>  state=<FSM state>
last update <age>`. This is the live, observable version of "distinguish
SCTP and HTTP": only sources `amf_xdp_enforce()` actually categorized as
NGAP ever get an entry here at all. An HTTP client hammering the same
interface will never appear in this dump, no matter how much traffic it
sends — the program returns (via the `iph->protocol != IPPROTO_SCTP`
check) long before it would compute a per-source key for it.

### `main()`

Mirrors the real `amf_loader` → `amf_xdp.o` boot order `../README.md`
describes, in one process instead of two, then adds the attach/monitor/
detach loop that role doesn't otherwise need:

1. **Resolve the interface.** `if_nametoindex(ifname)` — fails loudly
   with a clear message if the named interface doesn't exist, rather than
   letting `bpf_xdp_attach()` fail later with a less obvious error.
2. **Load `amf_xdp.o`.** `bpf_object__open_file()` + `bpf_object__load()`
   — this is also the point at which `sm_nodes`/`sm_edges` get
   created+pinned (or reused, if a real `amf_loader`/prior run already
   populated them) per `../sm_map.c`'s `LIBBPF_PIN_BY_NAME` declarations.
3. **Look up** the program (`amf_xdp_enforce`) and all four maps it
   declares (`sm_nodes`, `sm_edges`, `amf_xdp_stats`, `ue_state_map`) by
   name.
4. **(Re)populate the FSM table.** `fx_populate_nodes()`/
   `fx_populate_edges()`, unconditionally — an idempotent upsert
   (`BPF_ANY`), exactly like `amf_loader.c`'s `sm_map_populate()` runs
   every time `amf_loader` starts, regardless of prior state.
5. **Attach.**
   ```c
   __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
   bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
   ```
   - `XDP_FLAGS_SKB_MODE` (generic mode) works on any interface, including
     a veth pair, without needing native driver-level XDP support — the
     same portability tradeoff `../README.md`'s own `ip link set ... xdp`
     command implicitly makes.
   - `XDP_FLAGS_UPDATE_IF_NOEXIST` makes the attach **fail** instead of
     silently replacing whatever program is already attached — so running
     this monitor can never accidentally steal the program out from under
     a real production `amf_xdp.o` that's already running on the same
     interface.
6. **Install signal handlers** (`SIGINT`/`SIGTERM` → set a
   `volatile sig_atomic_t g_stop`, and record which signal in
   `g_stop_signal` so the final message can name it), same pattern
   `../amf_loader.c` uses.
7. **Monitor loop:** once a second:
   - **Check the interface itself is still the same device.** An XDP
     attachment lives on the kernel `net_device`, not on the interface
     *name* — if whatever owns this veth destroys and rebuilds it (by far
     the most common cause: a container that owns the other end
     restarting, e.g. an AMF/gNB container restarting as part of bringing
     up a UE simulator), the XDP attachment is destroyed right along with
     the old device, silently, with no signal delivered to this process
     at all. `if_nametoindex(ifname)` is re-checked every tick against the
     `ifindex` recorded at attach time:
     - **Same ifindex:** nothing to do, proceed to the stats check below.
     - **Different ifindex:** the device was torn down and a new one
       (with the same name) took its place — print that explicitly and
       `bpf_xdp_attach()` again onto the new ifindex, so the monitor keeps
       working across a container restart instead of going silently dark.
     - **ifindex 0 (name doesn't resolve at all):** the interface is
       simply gone and hasn't come back — print a diagnostic explaining
       there's nothing left to detach, and exit (`iface_lost = 1`).
   - **Read `amf_xdp_stats`.** If any of the three counters changed since
     the last tick, print a timestamped summary line
     (`PASS=n(+d) DROP=n(+d) STATE_INVALID=n(+d)`) plus a full
     `dump_ue_state_map()`. Stays silent on ticks where nothing changed
     (interface included), rather than printing a heartbeat line every
     second regardless.
8. **On exit:** if the loop broke because the interface was lost, there's
   nothing to detach (already reported above) — just close `obj` and
   return non-zero. Otherwise (Ctrl+C / `SIGTERM`), print which signal was
   received, `bpf_xdp_detach(ifindex, xdp_flags, NULL)` to remove the
   program from the interface, then `bpf_object__close(obj)` to close the
   program fd and every map fd this object owns.

### Why the interface-recreation check matters in practice

If you attach this monitor and then start a UE/gNB simulator (e.g.
UERANSIM) that causes the AMF (or whatever container owns the other end of
`veth5538fab`) to restart, Docker tears down that container's network
namespace and builds a brand new veth pair — even if the host-side name
comes back identical, it's a **different kernel object** with a
**different ifindex**, and the XDP program that was attached to the old
one is simply gone; nothing "detached" it in the sense of an explicit
`bpf_xdp_detach()` call, the whole device it was attached to stopped
existing. Before this check existed, the monitor would just keep running
in that state, holding real (but now-orphaned) map fds, printing nothing,
looking indistinguishable from "there's no traffic yet." The check above
makes that state visible immediately and, when the interface reappears
under the same name, self-heals by re-attaching rather than requiring a
manual restart.

If you instead see `test_xdp` itself print
`[*] Received signal N (...) -- detaching from ...` right after starting
the other tool, that's a *different* situation: something is actually
sending this process `SIGINT`/`SIGTERM` (a broad `pkill`, a shared process
group being torn down, the terminal session itself being recycled) — not
an interface problem at all. The two cases now produce visibly different
output, which earlier revisions of this file did not distinguish.

## Notes / things this monitor deliberately does NOT do

- **No assertions, no exit code.** This is an observability tool, not a
  test — see "Why a monitor instead of an automated test" above. If you
  want deterministic, CI-runnable coverage of the parsing logic itself,
  that's what a `BPF_PROG_TEST_RUN`-based test would be for; this file no
  longer is one.
- **Doesn't generate any traffic itself.** You need a real (or simulated)
  SCTP/NGAP source and some ordinary HTTP traffic on the same interface to
  see the two behaviors contrast. `ip netns`/`veth` pairs plus `curl` for
  the HTTP side, and a real or scripted SCTP association carrying an NGAP
  `InitialUEMessage` for the other, are outside this file's scope.
- **Rate limiting and FSM-mismatch flagging** (`amf_xdp_rate_map`,
  `STAT_DROP`, `STAT_STATE_INVALID` actually going non-zero) will show up
  in the monitor output if real traffic triggers them, but nothing here
  drives those cases deliberately — you'd need a real flood
  (>50 `InitialUEMessage`/s from one source) or a source already
  mid-registration receiving an out-of-spec label, respectively.
