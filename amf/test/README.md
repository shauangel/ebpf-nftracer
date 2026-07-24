# amf/test — sm_map.c eBPF map tests

Tests for the two `BPF_MAP_TYPE_HASH` maps declared in [`../sm_map.c`](../sm_map.c)
(`sm_nodes`, `sm_edges` — see [`../sm_map.h`](../sm_map.h) for their key/value
layout). Unlike a typical host-side unit test, these create and manipulate
**real kernel BPF maps** via libbpf, not a mock. There is no BPF *program*
compilation involved (no `clang -target bpf`, no skeleton) — hash maps are
created and read entirely from userspace through the `bpf()` syscall, which
is all these tests need to exercise.

## Requirements

- **Linux** with `CONFIG_BPF_SYSCALL` (any modern distro kernel).
- **libbpf** development headers/library installed (`libbpf-dev` on
  Debian/Ubuntu, `libbpf-devel` on Fedora), matching what [`../Makefile`](../Makefile)
  already requires for the rest of `amf/`.
- **Root**, or at minimum `CAP_BPF` (+ `CAP_SYS_ADMIN` on kernels older than
  5.8) — creating/populating a BPF map requires it. Each test binary checks
  `geteuid() == 0` itself at startup and exits with a clear message if not
  run as root, rather than letting every check fail with a confusing
  `EPERM`.
- **bpffs mounted at `/sys/fs/bpf`** — only needed for the pin/reopen test
  in `test_map_create`, matching the same requirement `sm_map.c`'s own
  top-of-file comment notes for the production loader.

These tests will not build on macOS/other non-Linux hosts; `make` refuses
outright (see `check-linux` in the Makefile) rather than failing with a
confusing missing-header error.

## Building and running

```sh
cd amf/test
make            # builds test_map_create, test_map_walk
sudo ./test_map_create
sudo ./test_map_walk
```

or, in one step:

```sh
sudo make -C amf/test test
```

Each binary prints one line per check it runs, `FAIL [test_name] file:line:
condition` for anything that fails, and a final `N checks, M failed`
summary. Exit code is `0` iff every check passed.

## Files

| File               | Purpose                                                         |
|--------------------|------------------------------------------------------------------|
| `framework.h`      | Minimal `CHECK`/`RUN_TEST` assertion macros, no external deps.  |
| `test_util.h`      | `require_root()`, plus helpers that call `bpf_map_create()` with the exact type/key/value/`max_entries` sm_map.c declares for `sm_nodes`/`sm_edges`. |
| `fixtures.h`       | The real 29-node/52-edge FSM table, mirrored 1:1 from [`../amf_comm.c`](../amf_comm.c)'s `sm_node_data[]`/`sm_edge_data[]` (itself mirrored from `amf/amf_state_machine.py`). Testing against the actual production table, not a handful of hand-picked entries, is what would catch a regression like the table outgrowing `SM_NODE_MAP_MAX_ENTRIES`/`SM_EDGE_MAP_MAX_ENTRIES`. Keep in sync with `amf_comm.c` by inspection. |
| `test_map_create.c`| eBPF map **creation** tests. |
| `test_map_walk.c`  | eBPF hash map **population + visiting** tests. |

## Test cases

### `test_map_create` — eBPF map creation

- **`test_create_sm_nodes_map`** / **`test_create_sm_edges_map`** — calls
  `bpf_map_create(BPF_MAP_TYPE_HASH, ...)` with `sm_map.h`'s declared
  key/value structs and `SM_NODE_MAP_MAX_ENTRIES`/`SM_EDGE_MAP_MAX_ENTRIES`,
  then reads the map back with `bpf_obj_get_info_by_fd()` and checks the
  **kernel's own report** of `type`/`key_size`/`value_size`/`max_entries`
  matches — not just that creation returned a valid fd.
- **`test_independent_creations_are_distinct_maps`** — two separately
  created (unpinned) maps must not alias each other. A safety check on the
  test helpers themselves: if this ever failed, every other test in the
  suite could be silently passing against one shared fd instead of two
  independent maps.
- **`test_map_rejects_insert_past_max_entries`** — fills a map to exactly
  `SM_NODE_MAP_MAX_ENTRIES`, confirms a further *distinct* key is rejected
  (`E2BIG`/`ENOSPC`) while re-updating an *existing* key at full capacity
  still succeeds. Exercises the real kernel capacity limit sm_map.c's
  `SM_NODE_MAP_MAX_ENTRIES`/`SM_EDGE_MAP_MAX_ENTRIES` constants exist to
  stay under.
- **`test_pin_and_reopen_resolve_to_same_map`** — pins a map to a
  test-local path under `/sys/fs/bpf`, writes an entry through the original
  fd, then opens the *same path* through a second, independent
  `bpf_obj_get()` call and confirms it reads back the same entry. This is
  the exact mechanism `sm_map.c` depends on for `amf_tracer.bpf.o` and
  `amf_xdp.o` — two separately loaded BPF objects — to share one populated
  `sm_nodes`/`sm_edges` instance instead of each getting its own empty
  copy.

### `test_map_walk` — eBPF hash map visiting

A `BPF_MAP_TYPE_HASH` has no "list all entries" syscall — the kernel only
supports "give me the key after this one" (`bpf_map_get_next_key()`), so
`walk_nodes()`/`walk_edges()` in this file implement that walk loop
directly, the same protocol any real consumer (e.g. a debugging tool
dumping `sm_nodes`) would have to use.

- **`test_walk_visits_every_populated_node_exactly_once`** /
  **`test_walk_visits_every_populated_edge_exactly_once`** — populates a
  map with the full `fixtures.h` table (all 29 nodes / 52 edges), walks it
  via `bpf_map_get_next_key()` + `bpf_map_lookup_elem()`, and checks every
  fixture entry was visited exactly once with the correct value (node
  `kind`, edge `to`) — and that nothing unexpected showed up.
- **`test_walk_is_repeatable`** — runs the walk twice back-to-back
  (restarting from `key=NULL`) and checks both passes visit the same
  count. Guards against a walk implementation that accidentally
  mutates/consumes entries as it iterates.
- **`test_point_lookup_known_entries`** — direct `bpf_map_lookup_elem()`
  checks against specific, meaningful entries: `REG_RECEIVED` is a
  `SM_KIND_NORMAL` node, the `UE/gNB --InitialUEMessage--> REG_RECEIVED`
  edge resolves correctly, and — mirroring the FSM's replay-detection
  design — a lookup using a *valid* label but the *wrong* `from` state
  (`NAS_SECURITY_PENDING` + `"replay/abnormal retry"`, a label that's only
  a real edge from `NAS_AUTHENTICATING`) correctly misses. This is the
  structural guarantee the composite `(from, label)` edge key exists to
  provide: a forged/replayed transition can't be validated just because
  its label matches *some* edge somewhere.
- **`test_delete_elem_removed_from_walk`** — deletes one entry with
  `bpf_map_delete_elem()`, confirms a direct lookup on it now misses, and
  confirms a subsequent walk visits exactly one fewer entry.
