# AMF eBPF Tracer

Instruments free5gc's AMF with eBPF so a userspace/in-kernel agent can reconstruct, in real time, entry into
each state of the 23-state threat-aware UE-registration FSM defined in [`amf_state_machine.py`](amf_state_machine.py)
/ [`doc/ebpf-hook-point.pdf`](doc/ebpf-hook-point.pdf) — and cross-check observed events against that FSM to
catch out-of-spec state transitions (forged, replayed, or out-of-order protocol messages), not just log them.

Two cooperating pieces:

- **Uprobe/tracepoint tracer** (`amf_tracer.bpf.c` + `amf_loader.c` + friends) — 43 uprobes on real free5gc Go
  symbols, deep inside the AMF process, with full post-NAS-decode visibility.
- **XDP packet enforcement** (`amf_xdp.c`) — attached at the N2 veth ingress, before any Go code runs; sees
  raw SCTP/NGAP bytes only, but can actually drop a packet.

Both share the same FSM graph (`sm_nodes`/`sm_edges`, pinned BPF maps — see [sm_map.c](#sm_maph--sm_mapc)),
so either layer can validate an observed transition against the same ground truth.

## Architecture

```
                     ┌─────────────────────────────┐
                     │        sm_map.c / .h         │
                     │  sm_nodes / sm_edges (pinned) │
                     │  sm_node_lookup()              │
                     │  sm_transition_lookup()        │
                     └───────────┬─────────┬─────────┘
                     #include    │         │   #include
              ┌──────────────────┘         └──────────────────┐
              ▼                                                ▼
  ┌────────────────────────┐                      ┌─────────────────────────┐
  │   amf_tracer.bpf.c      │                      │      amf_xdp.c           │
  │   43 uprobes + 6        │                      │   XDP @ veth5538fab      │
  │   tracepoints, post-NAS │                      │   raw SCTP/NGAP only     │
  │   decode visibility     │                      │   ue_state_map (private) │
  │   -- no per-UE state     │                      │   rate limit -> DROP     │
  │   map yet (see below)    │                      │   FSM check -> flag      │
  └────────────┬────────────┘                      └─────────────────────────┘
               │ loaded/attached by
               ▼
  ┌────────────────────────┐        ┌────────────────────────┐
  │  amf_functions.{h,c}     │◄──────│      amf_comm.{h,c}      │
  │  21 attach_target[]      │  used │  attach/detach mechanics │
  │  arrays, 43 targets       │  by   │  sm_map_populate()        │
  └────────────┬────────────┘        └────────────┬────────────┘
               │                                    │
               └──────────────┬─────────────────────┘
                              ▼
                       amf_loader.c (main)
             discover AMF -> load skeleton -> populate
             cgroup map + FSM map -> attach everything ->
                    drain ring buffer until Ctrl-C
```

## Modules

### `sm_map.h` / `sm_map.c`

The FSM itself (29 nodes, 52 edges, mirrored 1:1 from `amf_state_machine.py`), stored as two eBPF hash maps.

| Type | Fields | Purpose |
|---|---|---|
| `enum sm_node_kind` | `SM_KIND_NORMAL` / `FAILURE` / `ENDPOINT` | 13 normal states, 10 failure states, 6 endpoints (`UE/gNB`, `AMF`, `AUSF`, `UDM`, `PCF`, `SMF`) |
| `struct sm_node_key` | `char name[32]` | Key into `sm_nodes` |
| `struct sm_node_val` | `__u8 kind` | Value in `sm_nodes` |
| `struct sm_edge_key` | `char from[32], char label[48]` | Key into `sm_edges` |
| `struct sm_edge_val` | `char to[32]` | Value in `sm_edges` — the destination state |

`sm_map.c` is `#include`'d (never compiled standalone) into **two separate BPF objects** —
`amf_tracer.bpf.c` and `amf_xdp.c` — which are independently loaded and attached. Both declare
`sm_nodes`/`sm_edges` with `__uint(pinning, LIBBPF_PIN_BY_NAME)`, so instead of each object getting its own
empty map, both resolve to the **same** kernel map at `/sys/fs/bpf/sm_nodes` / `/sys/fs/bpf/sm_edges`.
Whichever loads first creates and pins it; `amf_loader.c` (via `sm_map_populate()`) is expected to run first
and do the actual population. **Requires bpffs mounted at `/sys/fs/bpf`** — without it, object load fails
outright.

Key functions (both `__always_inline`, safe to call from any uprobe/XDP handler):

- **`sm_node_lookup(name)`** — a state's kind (normal/failure/endpoint).
- **`sm_transition_lookup(from, label)`** — the core primitive. Given a believed current state and an
  observed event label, returns the FSM's expected next state, or `NULL` if `(from, label)` is not a valid
  edge. **`NULL` is the threat signal** — see the [demo](#demo-detecting-an-invalid-state-transition) below.

### `amf_functions.h` / `amf_functions.c`

Pure data, no functions: 21 `struct attach_target[]` arrays, one per FSM node, 43 uprobe targets total.
`func_name` strings are verified against `bin/amf` (see [`doc/verified_attach_points.txt`](doc/verified_attach_points.txt)).
Two states (`REPLAY_SUSPECTED`, `PDU_SESSION_REJECTED`) have no array — both reuse a probe already declared
under an earlier state. A disabled (`#if 0`) legacy block of 6 arrays / 22 targets hooks the old, non-FSM
`internal/sbi/processor.*` SBI-service callbacks — kept for reference only.

### `amf_comm.h` / `amf_comm.c`

Userspace glue: generic attach/detach mechanics + the FSM-map loader.

- `sm_map_populate(skel)` — loads the 29 nodes / 52 edges into `sm_nodes`/`sm_edges` via `bpf_map__update_elem()`.
- `attach_programs` / `detach_programs` — generic uprobe/uretprobe attach+detach for any `struct attach_target[]`.
- `attach_tracepoints` / `detach_tracepoints` — same shape, for kernel tracepoints.

### `amf_loader.c`

The tracer's `main()`. Seven-step pipeline: discover the AMF process → resolve its cgroup → load the BPF
skeleton → populate `amf_cgroup_map` → populate the FSM maps (`sm_map_populate`) → attach all 43 uprobes
(21 groups) → attach 6 syscall tracepoints → drain the ring buffer until Ctrl-C.

### `amf_tracer.bpf.c`

The uprobe/tracepoint BPF program. 4 maps (`events` ringbuf, `amf_cgroup_map`, `connect_scratch`,
`accept_scratch`) + 3 helpers (`new_event`, `is_amf_cgroup`, `read_sockaddr_in`) + 43 active uprobe handlers +
6 tracepoint handlers, plus `sm_nodes`/`sm_edges` pulled in via `#include "sm_map.c"`.

> **Status:** the 43 uprobe handlers each still just record `"<symbol> fired"` (`EVT_API_CALL`) — none of
> them call `sm_transition_lookup()` yet, and there is no per-UE state map on this side (`amf_xdp.c` has one;
> `amf_tracer.bpf.c` does not). See [What this demo needs that doesn't exist yet](#what-this-demo-needs-that-doesnt-exist-yet).

### `amf_xdp.c`

XDP packet **enforcement** on the AMF's N2 ingress, attached to `veth5538fab`. The one file that currently
exercises the full state-machine + per-entity-state pattern end-to-end.

| Piece | Type | Role |
|---|---|---|
| `amf_xdp_rate_map` | `LRU_HASH`, key=src IP | 1s sliding-window InitialUEMessage counter — the actual `XDP_DROP` trigger today |
| `amf_xdp_stats` | `ARRAY[3]` | `PASS`/`DROP`/`STATE_INVALID` counters, readable via `bpftool map dump` |
| `ue_state_map` | `LRU_HASH`, key=src IP (TODO: RAN-UE-NGAP-ID) | Per-source FSM state — private to this object, not shared (yet) |
| `ngap_procedure_label()` | `const char *(__u16)` | TODO stub: only `procedureCode 15` (InitialUEMessage) is categorized; everything else passes through untouched |
| `rate_limited()` | `int (__u32 src_ip, __u64 now)` | 1s / 50-packet InitialUEMessage rate limit per source IP |
| `amf_xdp_enforce()` | `SEC("xdp")` | parse → categorize → look up UE state → `sm_transition_lookup()` → update state or flag mismatch → rate-limit gate → PASS/DROP |

**Enforcement policy today:** only the rate limiter returns `XDP_DROP`. An FSM mismatch is logged and counted
but does **not** drop the packet — deliberately conservative, since categorization is one procedure code wide
and the UE key (source IP) collides multiple UEs behind one gNB/NAT address.

```
Attach : sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
Detach : sudo ip link set dev veth5538fab xdp off
Verify : ip link show dev veth5538fab
Stats  : bpftool map dump name amf_xdp_stats
```

### `xdp_ngap.c` (legacy, superseded)

The original passive version: parses Ethernet→IP→SCTP→NGAP, `bpf_printk`s the procedure code, always
`XDP_PASS`. Kept for reference; `amf_xdp.c` does everything this does plus real enforcement.

### `Makefile`

Builds only the uprobe/tracepoint tracer: compiles `amf_tracer.bpf.c` (which pulls in `sm_map.c`) into
`amf_tracer.bpf.o`, generates the skeleton, links `amf_loader.c` + `amf_comm.c` + `amf_functions.c` +
`../common.c` into the `amf_loader` binary. **No rule for `amf_xdp.c`** (or `xdp_ngap.c`) — both are
hand-compiled and attached via `ip link`.

### `doc/`

| File | What it is |
|---|---|
| `ebpf-hook-point.pdf` | Source-of-truth 23-state hook-point spec this whole tracer is built from |
| `amf_state_machine.py` | The networkx FSM definition `sm_map.c`/`amf_comm.c` mirror 1:1 |
| `missing_attach_points.txt` / `verified_attach_points.txt` | Gap analysis + `bin/amf` symbol verification |
| `progress0717.pdf` | Narrative progress report |
| `doc_0717.pdf` | Exhaustive function/variable reference for `amf_comm.c`, `amf_functions.c`, `amf_loader.c`, `amf_tracer.bpf.c` |
| `amf_modules_demo_0721.pdf` | Module reference + this same demo, formatted as a standalone PDF |

## Building & Running

```sh
# uprobe/tracepoint tracer
make
sudo ./amf_loader

# XDP enforcement (separate object, not built by the Makefile)
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I.. -c amf_xdp.c -o amf_xdp.o
sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
```

Run `amf_loader` **first** — `sm_nodes`/`sm_edges` need to exist and be populated before `amf_xdp.o` loads,
or it'll create+pin them empty and every FSM lookup will simply miss until the tracer catches up.

## Demo: Detecting an Invalid State Transition

**Scenario:** a malicious or compromised UE sends an unexpected NAS Authentication Failure message for a
session the AMF already knows has moved past authentication — the AMF isn't waiting on an authentication
reply for this UE anymore; it's waiting on a Security Mode Complete instead. The message claims a response
never happened, but the FSM's ground truth for this UE says it did.

This is deliberately *not* "any Authentication Failure while in `NAS_AUTHENTICATING`" — per `sm_edges`, that
case already has a legitimate edge (`"replay/abnormal retry" → REPLAY_SUSPECTED`). The actually-invalid case
is a Failure arriving *after* the UE's real state has already moved on, which has no edge at all — exactly
the class of forged/replayed/out-of-order message a flat event log can't distinguish from noise, but an FSM
check catches immediately.

```
T0  UE  -> AMF   NGAP InitialUEMessage
        amf_ngap_ue_msg + amf_handle_nas fire
        sm_transition_lookup("UE/gNB", "InitialUEMessage") -> REG_RECEIVED
        ue_state[UE] = REG_RECEIVED

T1  ... (context lookup / identity / auth-vector steps, elided)
        ue_state[UE] progresses -> AUTH_VECTOR_PENDING

T2  AMF <-> AUSF  AuthenticationProcedure, Nausf_UEAuthentication_Authenticate -> success
        amf_auth_proc, amf_ausf_auth (uretprobe) fire
        sm_transition_lookup("AUTH_VECTOR_PENDING", "AUSF success") -> NAS_AUTHENTICATING
        ue_state[UE] = NAS_AUTHENTICATING

T3  AMF -> UE     NAS Authentication Request          (amf_auth_req fires)

T4  UE  -> AMF    NAS Authentication Response, valid RES*
        amf_auth_resp fires -> label "RES* valid"
        sm_transition_lookup("NAS_AUTHENTICATING", "RES* valid") -> NAS_SECURITY_PENDING   [MATCH]
        ue_state[UE] = NAS_SECURITY_PENDING
        AMF -> UE: Security Mode Command; now waiting on Security Mode Complete, NOT auth anything.

T5  ATTACK  ??? -> AMF   NAS Authentication Failure  (cause = MAC failure, or a replayed/forged frame)
        amf_auth_fail fires -> label "replay/abnormal retry" (the only label HandleAuthenticationFailure maps to)
        from_state = ue_state[UE] = NAS_SECURITY_PENDING   (NOT NAS_AUTHENTICATING anymore)
        sm_transition_lookup("NAS_SECURITY_PENDING", "replay/abnormal retry") -> NULL   [NO SUCH EDGE]
        ==> FLAGGED: out-of-spec transition. ue_state[UE] left unchanged at NAS_SECURITY_PENDING.
```

**Why `NAS_SECURITY_PENDING` has no matching edge** — its only outgoing edges:

| from | to | label |
|---|---|---|
| `NAS_SECURITY_PENDING` | `UE/gNB` | `Security Mode Command` |
| `UE/gNB` | `NAS_SECURITY_PENDING` | `Security Mode Complete` |
| `NAS_SECURITY_PENDING` | `UDM_REGISTERING` | `integrity success` |
| `NAS_SECURITY_PENDING` | `SECURITY_FAILED` | `integrity fail` |
| `NAS_SECURITY_PENDING` | `SECURITY_POLICY_VIOLATION` | `NULL/invalid algorithm` |

None of these is labeled `"replay/abnormal retry"` (or anything Authentication-Failure-shaped) — that label
only exists as an outgoing edge of `NAS_AUTHENTICATING`. A lookup keyed on `(NAS_SECURITY_PENDING,
"replay/abnormal retry")` is guaranteed to miss, regardless of what the actual attack payload looks like —
**the detection is structural, not signature-based.**

**Expected operator-visible output:**

```
bpf_printk: "amf_tracer: FSM mismatch ue=<key> from=NAS_SECURITY_PENDING label=Authentication Failure"
amf_tracer_stats[STATE_INVALID]++   (mirrors amf_xdp_stats' STAT_STATE_INVALID)
```

### What this demo needs that doesn't exist yet

The mechanism (`sm_transition_lookup`, pinned `sm_edges`, a per-entity state map, a mismatch counter) is
fully built and already running — in `amf_xdp.c`, for NGAP InitialUEMessage. It is **not yet wired into
`amf_tracer.bpf.c`**, which is where it needs to run for this specific scenario: Authentication Response vs.
Authentication Failure are both NAS (5GMM) messages carried inside an NGAP `UplinkNASTransport` IE — XDP only
ever sees the outer NGAP procedureCode and cannot tell them apart without full ASN.1 PER + NAS decode. Only
the Go binary (and therefore only a uprobe on the already-decoded call, e.g. `amf_auth_resp`/`amf_auth_fail`)
can see which one actually arrived.

- Add a per-UE `ue_state_map` to `amf_tracer.bpf.c` (identical shape to `amf_xdp.c`'s, but keyed on something
  extractable from the Go call's arguments — e.g. the `AmfUe`/`RanUe` identity — rather than source IP, since
  uprobes have real per-UE granularity available that XDP does not).
- In `amf_auth_resp` and `amf_auth_fail`, look up the UE's current state, call `sm_transition_lookup(from,
  label)` with the appropriate label (`"RES* valid"`/`"RES* invalid"` for the Response handler,
  `"replay/abnormal retry"` for the Failure handler), and on `NULL`, flag it instead of silently recording a
  bare `EVT_API_CALL`.
- The remaining open question is exactly how to derive the per-UE key from a Go uprobe's arguments
  (register-based Go calling convention, reading a pointer field off the `AmfUe` struct) — not yet designed,
  flagged here as the next concrete step rather than glossed over.

**Illustrative sketch** (not applied to `amf_tracer.bpf.c` — shows the shape of the change):

```c
SEC("uprobe/amf_auth_fail")
int amf_auth_fail(struct pt_regs *ctx)
{
    struct event *e = new_event(EVT_API_CALL);
    if (!e) return 0;
    __builtin_memcpy(e->api, "NASAUTH:HandleFail", 18);

    __u32 ue_key = /* TODO: derive from ctx args, e.g. AmfUe identity */ 0;
    struct ue_val *ue = ue_state_lookup(ue_key);
    const char *from_state = ue ? ue->state : "NAS_AUTHENTICATING";

    struct sm_edge_val *edge = sm_transition_lookup(from_state, "replay/abnormal retry");
    if (!edge) {
        bpf_printk("amf_tracer: FSM mismatch ue=%u from=%s", ue_key, from_state);
        /* bump a STAT_STATE_INVALID-style counter here */
    } else {
        ue_state_set(ue_key, edge->to, bpf_ktime_get_ns());
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```
