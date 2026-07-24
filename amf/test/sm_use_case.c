/*
 * End-to-end use case simulation of the walk-through in
 * ../README.md's toy demo:
 * a UE registers normally (T0-T4), then an attacker replays a forged NAS
 * message out of sequence (T5) and the FSM catches it.
 *
 * Inspect the exact state the FSM ended up in with:
 *   sudo bpftool map dump pinned /sys/fs/bpf/sm_use_case_nodes
 *   sudo bpftool map dump pinned /sys/fs/bpf/sm_use_case_edges
 */

#include <errno.h>    /* errno, ENOENT -- to tell "no such edge" apart from a real error */
#include <stdio.h>    /* printf/fprintf/snprintf for the narration and pin-path messages */
#include <string.h>   /* strerror(), strcmp() are not used directly but snprintf-adjacent string ops are */
#include <unistd.h>   /* close(), unlink() */

#include <bpf/bpf.h>  /* bpf_map_lookup_elem/bpf_obj_pin/bpf_obj_get -- the real bpf() syscall wrappers */

#include "framework.h" /* CHECK()/RUN_TEST()/test_summary() -- same harness the other two suites use */
#include "test_util.h" /* require_root(), create_sm_nodes_map()/create_sm_edges_map() */
#include "fixtures.h"   /* fx_populate_nodes()/fx_populate_edges() -- the real 29/52-entry FSM table */
#include "../sm_map.h"  /* struct sm_node_key/val, struct sm_edge_key/val, SM_NAME_MAX, SM_LABEL_MAX */

/* Pin paths this demo uses */
#define SM_USE_CASE_NODES_PIN "/sys/fs/bpf/sm_use_case_nodes"
#define SM_USE_CASE_EDGES_PIN "/sys/fs/bpf/sm_use_case_edges"

/* ── userspace equivalents of sm_map.c's in-kernel lookup helpers ──────
 * sm_map.c's own sm_node_lookup()/sm_transition_lookup() are `static
 * __always_inline`, compiled only as part of a BPF program (they call
 * bpf_map_lookup_elem() on the BPF-side map *object*, not an fd) -- they
 * cannot be linked into or called from a normal userspace binary. These
 * two functions do the exact same key-construction + lookup, just via
 * the fd-based libbpf API, against the exact same kernel map instance,
 * so what they return is guaranteed identical to what a uprobe/XDP
 * handler calling the real sm_transition_lookup() would see. */

/* Look up a single node's kind (SM_KIND_NORMAL/FAILURE/ENDPOINT).
 * fd:   the open sm_nodes map fd
 * name: the node name to look up (e.g. "REG_RECEIVED")
 * out:  filled in on success (fd >= 0 and the key is present)
 * Returns 0 on a hit, -ENOENT on a miss, or another negative errno on a
 * real syscall failure. */
static int demo_node_lookup(int fd, const char *name, struct sm_node_val *out)
{
    struct sm_node_key key = {};                          /* zero every byte first ... */
    snprintf(key.name, sizeof(key.name), "%s", name);      /* ... then copy in the name, matching sm_map_populate()'s own snprintf-into-zeroed-key pattern so keys hash identically */

    if (bpf_map_lookup_elem(fd, &key, out) == 0)            /* real syscall: ask the kernel hash map for this exact key */
        return 0;                                            /* found it */
    return -errno;                                           /* not found (ENOENT) or a real error -- caller decides which */
}

/* Look up the FSM's expected next state for (from, label).
 * fd:    the open sm_edges map fd
 * from:  the state we believe we're in right now
 * label: the event/message label that just arrived
 * out:   filled in on success with the destination state
 * Returns 0 on a hit, -ENOENT if (from, label) is not a valid edge --
 * exactly the "NULL means invalid transition" contract sm_map.c's
 * in-kernel sm_transition_lookup() documents. */
static int demo_transition_lookup(int fd, const char *from, const char *label,
                                   struct sm_edge_val *out)
{
    struct sm_edge_key key = {};                              /* zero-padded key, same requirement as sm_node_key above */
    snprintf(key.from,  sizeof(key.from),  "%s", from);        /* current state goes in the "from" half of the composite key */
    snprintf(key.label, sizeof(key.label), "%s", label);       /* the observed event label goes in the "label" half */

    if (bpf_map_lookup_elem(fd, &key, out) == 0)                /* composite-key lookup: only matches if THIS EXACT (from,label) pair was ever inserted */
        return 0;
    return -errno;
}

/* ── the simulated UE registration timeline ─────────────────────────────
 * Each entry is one simulated protocol event. `event_label` is the exact
 * sm_edges label string that event maps to (see amf_comm.c's
 * sm_edge_data[] / fixtures.h's fx_edges[] -- these strings must match
 * one of those table entries character-for-character, or the lookup will
 * simply miss). `is_attack` marks the one entry (T5) where a miss is the
 * CORRECT, expected outcome instead of a test failure. */
struct demo_step {
    const char *t_label;     /* timeline marker printed before the step, e.g. "T0" */
    const char *narrative;   /* human-readable description of the simulated event */
    const char *event_label; /* the sm_edges label to look up from the CURRENT state */
    int         is_attack;   /* 1 => a miss here is success (attack correctly flagged) */
};

static const struct demo_step demo_steps[] = {
    /* T0: the UE's very first message. Looked up FROM "UE/gNB" (a real
     * SM_KIND_ENDPOINT node in sm_nodes, not a state) -- current_state
     * starts at "UE/gNB" below for exactly this reason. */
    { "T0",
      "UE/gNB -> AMF   NGAP InitialUEMessage (UE begins registration)",
      "InitialUEMessage", 0 },

    /* T1: AMF has decoded the NAS Registration Request inside that
     * InitialUEMessage and starts looking for an existing UE context. */
    { "T1",
      "AMF validates the NAS envelope, starts a UE-context lookup",
      "valid NAS", 0 },

    /* T2: first-time registration -- no context exists yet, so the AMF
     * has to ask the UE who it is. */
    { "T2",
      "No existing context found (first-time registration) -> AMF requests UE identity",
      "context unavailable", 0 },

    /* T3: the UE answers with its identity, so the AMF can now request
     * authentication vectors from the AUSF. */
    { "T3",
      "UE responds with its identity -> AMF requests auth vectors from AUSF",
      "identity available", 0 },

    /* T4: AUSF returns a usable vector -> AMF starts NAS authentication
     * proper (sends an Authentication Request, starts expecting a
     * Response). This is the last LEGITIMATE step. */
    { "T4",
      "AUSF returns a valid authentication vector -> AMF begins NAS authentication",
      "AUSF success", 0 },

    /* T5 -- THE ATTACK. A forged/replayed NAS Security Mode Complete
     * shows up claiming the UE already finished a Security Mode Command
     * exchange. But per the walk above, the AMF's real ue_state is still
     * NAS_AUTHENTICATING -- it never sent a Security Mode Command for
     * this UE, so it can't have gotten a Complete back. "Security Mode
     * Complete" IS a real label in the FSM (see fixtures.h: it's the
     * edge UE/gNB -> NAS_SECURITY_PENDING), just not FROM
     * NAS_AUTHENTICATING -- so the composite (from,label) lookup below
     * is guaranteed to miss, structurally, the same way the README's own
     * "replayed Authentication Failure" example misses. */
    { "T5 [ATTACK]",
      "??? -> AMF   forged/replayed NAS Security Mode Complete "
      "(AMF never sent a Security Mode Command for this UE yet)",
      "Security Mode Complete", 1 },
};

#define DEMO_STEP_COUNT (sizeof(demo_steps) / sizeof(demo_steps[0]))

/* Runs the whole timeline against two already-populated, already-pinned
 * map fds, printing each step as it happens. */
static void run_demo(int nodes_fd, int edges_fd)
{
    /* current_state tracks ue_state[UE] from the README's demo -- it
     * starts as the initiating endpoint ("UE/gNB"), and from T0 onward
     * is OVERWRITTEN ONLY from a real edge's `.to` field (see the
     * memcpy-via-snprintf below), never typed in by hand. */
    char current_state[SM_NAME_MAX];
    snprintf(current_state, sizeof(current_state), "%s", "UE/gNB");

    printf("\n=== sm_use_case: simulated UE registration + attack ===\n");
    printf("ue_state[UE] starts at: %s\n\n", current_state);

    for (size_t i = 0; i < DEMO_STEP_COUNT; i++) {
        const struct demo_step *step = &demo_steps[i];        /* the step we're about to simulate */
        struct sm_edge_val edge = {};                          /* will hold the kernel's answer, if any */

        printf("%-11s %s\n", step->t_label, step->narrative);  /* narrate the simulated protocol event first */
        printf("            sm_transition_lookup(\"%s\", \"%s\")",
               current_state, step->event_label);              /* echo the exact (from,label) key we're about to look up */

        int ret = demo_transition_lookup(edges_fd, current_state,
                                          step->event_label, &edge); /* the real map lookup -- this line is the whole test */

        if (ret == 0) {
            /* Hit: print the destination the KERNEL returned (never a
             * literal), then adopt it as the new current_state. */
            printf(" -> %s   [MATCH]\n", edge.to);
            CHECK(!step->is_attack); /* T5 hitting would mean the attack was NOT caught -- that's a failure */
            snprintf(current_state, sizeof(current_state), "%s", edge.to); /* advance the simulated UE's state -- copied straight from the map's value, not authored here */
        } else {
            /* Miss: for T0-T4 this is a real bug (fixture/path problem);
             * for T5 this IS the security property under test. */
            printf(" -> NO SUCH EDGE\n");
            CHECK(ret == -ENOENT);   /* must be a genuine miss, not some other syscall failure */
            if (step->is_attack) {
                printf("            ==> FLAGGED: out-of-spec transition. "
                       "ue_state[UE] left unchanged at %s\n", current_state);
                CHECK(step->is_attack); /* tautological, but keeps the pass/fail symmetric with the hit branch above */
            } else {
                fprintf(stderr,
                        "            unexpected miss on a LEGITIMATE step -- "
                        "fixtures.h and this demo's step table have drifted apart\n");
                CHECK(0); /* hard-fail: a non-attack step must never miss */
            }
        }
        printf("\n");
    }

    printf("Final ue_state[UE] = %s\n", current_state);        /* where the simulated UE ended up */

    /* Bonus: look the final state up in sm_nodes too, to show sm_nodes
     * (not just sm_edges) is real and populated -- prints whether the
     * UE's final state is itself a normal/failure/endpoint node. */
    struct sm_node_val node = {};
    if (demo_node_lookup(nodes_fd, current_state, &node) == 0) {
        static const char *kind_name[] = { "NORMAL", "FAILURE", "ENDPOINT" };
        printf("sm_nodes[\"%s\"].kind = %s\n", current_state, kind_name[node.kind]);
    }
}

int main(int argc, char **argv)
{
    require_root(argc > 0 ? argv[0] : "sm_use_case"); /* creates/populates/pins real kernel maps -- needs CAP_BPF, i.e. root */

    printf("sm_use_case:\n");

    /* Clean up any pin left over from a previous (possibly interrupted)
     * run so this one starts from a known-empty map, not stale state. */
    unlink(SM_USE_CASE_NODES_PIN);
    unlink(SM_USE_CASE_EDGES_PIN);

    int nodes_fd = create_sm_nodes_map("sm_use_case_nodes"); /* real BPF_MAP_TYPE_HASH, sm_map.h's exact layout */
    int edges_fd = create_sm_edges_map("sm_use_case_edges"); /* same, for sm_edges */
    CHECK(nodes_fd >= 0 && edges_fd >= 0);
    if (nodes_fd < 0 || edges_fd < 0) {
        fprintf(stderr, "sm_use_case: bpf_map_create failed: %s\n", strerror(errno));
        return 1; /* nothing to pin/populate/walk -- bail out before touching either fd further */
    }

    CHECK(fx_populate_nodes(nodes_fd) == 0); /* load all 29 real FSM nodes */
    CHECK(fx_populate_edges(edges_fd) == 0); /* load all 52 real FSM edges */

    /* Pin BOTH maps to bpffs so they outlive this process -- see the
     * file header comment for why (this is the whole point of this file
     * vs. the ephemeral maps in test_map_create.c/test_map_walk.c). */
    CHECK(bpf_obj_pin(nodes_fd, SM_USE_CASE_NODES_PIN) == 0);
    CHECK(bpf_obj_pin(edges_fd, SM_USE_CASE_EDGES_PIN) == 0);

    run_demo(nodes_fd, edges_fd); /* the actual simulation + narration (see above) */

    /* Closing these fds does NOT destroy the maps -- they're pinned, so
     * bpffs keeps them alive until something explicitly unlinks the pin
     * path (or the filesystem holding bpffs is unmounted). */
    close(nodes_fd);
    close(edges_fd);

    printf("\nMaps left pinned for inspection:\n");
    printf("  sudo bpftool map dump pinned %s\n", SM_USE_CASE_NODES_PIN);
    printf("  sudo bpftool map dump pinned %s\n", SM_USE_CASE_EDGES_PIN);
    printf("Remove them with:\n");
    printf("  sudo rm %s %s\n", SM_USE_CASE_NODES_PIN, SM_USE_CASE_EDGES_PIN);

    return test_summary(); /* non-zero exit iff any CHECK() above failed */
}
