/*
 * test_sm_fsm_walk.c — state-transition ("walk") tests against the REAL
 * FSM: sm_map.c's actual sm_transition_lookup() logic, loaded with the
 * actual production table from sm_map_data.c (the same data
 * amf_comm.c's sm_map_populate() puts in the live sm_edges BPF map).
 *
 * Each test enters a state, feeds it an observed event label, and prints
 * the transition sm_transition_lookup() resolves ("A --[label]--> B", or
 * "(NO SUCH TRANSITION)" for a NULL/rejected hop) -- both to eyeball and
 * as a CHECK()ed assertion of the expected destination. Longer walks
 * chain several hops end to end to prove a whole real registration path
 * (or failure path) resolves exactly as amf_state_machine.py intends.
 *
 * See test_sm_map.c for why sm_map.c is #include'd directly (not linked)
 * and why the off_t dance around it is needed on macOS; see
 * test_sm_map_data.c for data-integrity checks on the table itself. This
 * file is the third leg: real logic + real data, exercised together.
 */

#define off_t __vmlinux_unused_off_t
#include "../sm_map.c"
#undef off_t

#include <stdio.h>
#include <string.h>

#include "../sm_map_data.h"
#include "framework.h"

/* ── Mock sm_nodes / sm_edges backing store, populated from the REAL
 * sm_node_data/sm_edge_data table (see test_sm_map.c for why dispatch is
 * done by &sm_nodes/&sm_edges pointer identity). ─────────────────────── */

static struct {
    struct sm_node_key keys[SM_NODE_MAP_MAX_ENTRIES];
    struct sm_node_val vals[SM_NODE_MAP_MAX_ENTRIES];
    size_t count;
} node_store;

static struct {
    struct sm_edge_key keys[SM_EDGE_MAP_MAX_ENTRIES];
    struct sm_edge_val vals[SM_EDGE_MAP_MAX_ENTRIES];
    size_t count;
} edge_store;

void *bpf_map_lookup_elem(void *map, const void *key)
{
    if (map == (void *)&sm_nodes) {
        for (size_t i = 0; i < node_store.count; i++)
            if (memcmp(&node_store.keys[i], key, sizeof(struct sm_node_key)) == 0)
                return &node_store.vals[i];
        return NULL;
    }
    if (map == (void *)&sm_edges) {
        for (size_t i = 0; i < edge_store.count; i++)
            if (memcmp(&edge_store.keys[i], key, sizeof(struct sm_edge_key)) == 0)
                return &edge_store.vals[i];
        return NULL;
    }
    return NULL;
}

/* Mirrors amf_comm.c's sm_map_populate() exactly, just targeting the mock
 * store instead of a real skeleton's bpf_map__update_elem(). Loads the
 * full real table once per test run. */
static void load_real_fsm(void)
{
    node_store.count = 0;
    for (size_t i = 0; i < sm_node_data_count; i++) {
        struct sm_node_key key = {};
        struct sm_node_val val = {};
        snprintf(key.name, sizeof(key.name), "%s", sm_node_data[i].name);
        val.kind = (__u8)sm_node_data[i].kind;
        node_store.keys[node_store.count] = key;
        node_store.vals[node_store.count] = val;
        node_store.count++;
    }

    edge_store.count = 0;
    for (size_t i = 0; i < sm_edge_data_count; i++) {
        const struct sm_edge_def *ed = &sm_edge_data[i];
        struct sm_edge_key key = {};
        struct sm_edge_val val = {};
        snprintf(key.from,  sizeof(key.from),  "%s", ed->from);
        snprintf(key.label, sizeof(key.label), "%s", ed->label);
        snprintf(val.to,    sizeof(val.to),    "%s", ed->to);
        edge_store.keys[edge_store.count] = key;
        edge_store.vals[edge_store.count] = val;
        edge_store.count++;
    }
}

/* Enter state `from`, feed it event `label`, print what
 * sm_transition_lookup() resolves. Returns the next state (a pointer
 * into the mock edge_store, valid until the next load_real_fsm()), or
 * NULL if (from,label) has no edge -- the FSM's own "flag this" signal. */
static const char *step(const char *from, const char *label)
{
    struct sm_edge_val *e = sm_transition_lookup(from, label);
    printf("    %-24s --[%s]--> %s\n",
           from, label, e ? e->to : "(NO SUCH TRANSITION)");
    return e ? e->to : NULL;
}

/* ── The literal ask: enter state A, print next state B ─────────────── */

static void test_single_hop_prints_next_state(void)
{
    load_real_fsm();

    const char *next = step("NAS_AUTHENTICATING", "RES* valid");
    CHECK(next != NULL);
    if (next) CHECK_STREQ(next, "NAS_SECURITY_PENDING");
}

/* ── Full golden-path walk: every hop is a real edge from sm_edge_data,
 * strung together into the complete happy-path UE registration, exactly
 * as amf_state_machine.py / doc/ebpf-hook-point.pdf lay it out. ───────── */

static void test_walk_full_registration_golden_path(void)
{
    load_real_fsm();
    printf("  golden path:\n");

    const char *s = "UE/gNB";
    s = step(s, "InitialUEMessage");        CHECK(s && strcmp(s, "REG_RECEIVED") == 0);
    s = step(s, "valid NAS");               CHECK(s && strcmp(s, "CONTEXT_LOOKUP") == 0);
    s = step(s, "context unavailable");     CHECK(s && strcmp(s, "IDENTITY_PENDING") == 0);
    s = step(s, "identity available");      CHECK(s && strcmp(s, "AUTH_VECTOR_PENDING") == 0);
    s = step(s, "AUSF success");            CHECK(s && strcmp(s, "NAS_AUTHENTICATING") == 0);
    s = step(s, "RES* valid");              CHECK(s && strcmp(s, "NAS_SECURITY_PENDING") == 0);
    s = step(s, "integrity success");       CHECK(s && strcmp(s, "UDM_REGISTERING") == 0);
    s = step(s, "success");                 CHECK(s && strcmp(s, "SUBSCRIPTION_LOADING") == 0);
    s = step(s, "valid subscription");      CHECK(s && strcmp(s, "POLICY_ASSOCIATING") == 0);
    s = step(s, "policy success");          CHECK(s && strcmp(s, "UE_CONTEXT_READY") == 0);
    s = step(s, "PDU session request");     CHECK(s && strcmp(s, "SM_CONTEXT_PENDING") == 0);
    s = step(s, "SMF success");             CHECK(s && strcmp(s, "INITIAL_CONTEXT_SETUP") == 0);
    s = step(s, "setup success");           CHECK(s && strcmp(s, "REGISTERED_CONNECTED") == 0);
}

/* ── A real failure path: AUSF rejects the auth vector request, AMF
 * tears the partial context down. ──────────────────────────────────── */

static void test_walk_auth_rejection_failure_path(void)
{
    load_real_fsm();
    printf("  auth-rejection failure path:\n");

    const char *s = "AUTH_VECTOR_PENDING";
    s = step(s, "AUSF reject");                  CHECK(s && strcmp(s, "AUTH_FAILED") == 0);
    s = step(s, "release partial context");       CHECK(s && strcmp(s, "CLEANUP_REQUIRED") == 0);
}

/* ── README's "Detecting an Invalid State Transition" demo, replayed
 * against the real table: a forged/replayed Authentication Failure
 * arriving once the UE's real state has already moved on to
 * NAS_SECURITY_PENDING has no edge and must be flagged (NULL), even
 * though "replay/abnormal retry" is a perfectly real label from
 * NAS_AUTHENTICATING. ──────────────────────────────────────────────── */

static void test_walk_rejects_replayed_auth_failure(void)
{
    load_real_fsm();
    printf("  replay-attack scenario:\n");

    /* Legitimate: NAS_AUTHENTICATING really has this edge. */
    const char *legit = step("NAS_AUTHENTICATING", "replay/abnormal retry");
    CHECK(legit != NULL);
    if (legit) CHECK_STREQ(legit, "REPLAY_SUSPECTED");

    /* Attack: same label, but the UE has already moved on. */
    const char *attack = step("NAS_SECURITY_PENDING", "replay/abnormal retry");
    CHECK(attack == NULL);
}

int main(void)
{
    printf("test_sm_fsm_walk:\n");

    RUN_TEST(test_single_hop_prints_next_state);
    RUN_TEST(test_walk_full_registration_golden_path);
    RUN_TEST(test_walk_auth_rejection_failure_path);
    RUN_TEST(test_walk_rejects_replayed_auth_failure);

    return test_summary();
}
