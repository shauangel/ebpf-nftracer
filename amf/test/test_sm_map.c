/*
 * test_sm_map.c — unit tests for amf/sm_map.c: the key-encoding helpers
 * (sm_key_set_name/sm_key_set_label) and the two lookup primitives
 * (sm_node_lookup/sm_transition_lookup) that amf_tracer.bpf.c and
 * amf_xdp.c both rely on to validate FSM transitions in-kernel.
 *
 * sm_map.c is #include'd directly (not linked) so its `static
 * __always_inline` functions -- normally only reachable from inside a BPF
 * program -- are callable here like any other function in this
 * translation unit. mock_bpf.h stands in for <bpf/bpf_helpers.h>; the
 * bpf_map_lookup_elem() it prototypes is implemented below, backed by a
 * couple of plain arrays instead of a real kernel BPF_MAP_TYPE_HASH.
 *
 * Scope: sm_map.c's own logic only. The 29-node/52-edge FSM data table
 * itself lives in amf_comm.c (sm_node_data/sm_edge_data) and isn't
 * exercised here -- amf_comm.c pulls in amf_comm.h -> amf_tracer.skel.h
 * -> <bpf/libbpf.h>, which requires libbpf installed and isn't available
 * on every dev machine. Small, explicit fixtures are used instead, one
 * per test, rather than replaying the full production table.
 *
 * shim/bpf/bpf_helpers.h (found via -I, see Makefile) supplies the
 * SEC()/__uint()/__type()/bpf_map_lookup_elem() pieces sm_map.c itself
 * `#include <bpf/bpf_helpers.h>`s.
 *
 * vmlinux.h -- a straight BTF dump of every kernel type, included by
 * sm_map.c -- typedefs its own kernel-flavored `off_t` (long), which on
 * macOS collides with <stdio.h>'s `off_t` (long long, via
 * sys/_types/_off_t.h). sm_map.c/sm_map.h never touch off_t, so the value
 * doesn't matter here; rename vmlinux.h's copy out of the way for the
 * duration of the include so Darwin's own off_t typedef (pulled in below
 * by <stdio.h>) is untouched. */
#define off_t __vmlinux_unused_off_t
#include "../sm_map.c"
#undef off_t

#include <stdio.h>
#include <string.h>

#include "framework.h"

/* ── Mock sm_nodes / sm_edges backing store ──────────────────────────────
 * Dispatches on the address of sm_map.c's own `sm_nodes`/`sm_edges`
 * globals (real pointer identity, no size info needed from the caller --
 * exactly like the kernel's map fd does it, just resolved at compile time
 * here instead of at BPF-verifier time). Linear scan is plenty fast at
 * SM_NODE_MAP_MAX_ENTRIES/SM_EDGE_MAP_MAX_ENTRIES (64/128).
 * ────────────────────────────────────────────────────────────────────── */

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

static void mock_reset(void)
{
    node_store.count = 0;
    edge_store.count = 0;
}

/* Mirrors amf_comm.c's sm_map_populate() shape (snprintf into a
 * zero-initialized key), just writing into the mock store instead of via
 * bpf_map__update_elem(). */
static void mock_add_node(const char *name, enum sm_node_kind kind)
{
    struct sm_node_key key = {};
    struct sm_node_val val = {};
    snprintf(key.name, sizeof(key.name), "%s", name);
    val.kind = (__u8)kind;
    node_store.keys[node_store.count] = key;
    node_store.vals[node_store.count] = val;
    node_store.count++;
}

static void mock_add_edge(const char *from, const char *label, const char *to)
{
    struct sm_edge_key key = {};
    struct sm_edge_val val = {};
    snprintf(key.from,  sizeof(key.from),  "%s", from);
    snprintf(key.label, sizeof(key.label), "%s", label);
    snprintf(val.to,    sizeof(val.to),    "%s", to);
    edge_store.keys[edge_store.count] = key;
    edge_store.vals[edge_store.count] = val;
    edge_store.count++;
}

/* ── sm_key_set_name / sm_key_set_label ─────────────────────────────── */

static void test_sm_key_set_name_copies_short_string(void)
{
    char dst[SM_NAME_MAX] = {0};
    sm_key_set_name(dst, "REG_RECEIVED");
    CHECK_STREQ(dst, "REG_RECEIVED");
    CHECK(dst[SM_NAME_MAX - 1] == '\0');
}

static void test_sm_key_set_name_truncates_long_string(void)
{
    /* 40 chars, well past SM_NAME_MAX (32) */
    const char *too_long = "THIS_NAME_IS_DEFINITELY_TOO_LONG_TO_FIT";
    char dst[SM_NAME_MAX] = {0};
    sm_key_set_name(dst, too_long);

    CHECK(memcmp(dst, too_long, SM_NAME_MAX - 1) == 0);
    /* sm_key_set_name never writes the last byte itself -- callers are
     * expected to start from a zeroed buffer (see sm_map.c's comment on
     * sm_node_key/sm_edge_key); verify that contract holds. */
    CHECK(dst[SM_NAME_MAX - 1] == '\0');
}

static void test_sm_key_set_name_empty_string(void)
{
    char dst[SM_NAME_MAX];
    memset(dst, 0xAA, sizeof(dst));
    sm_key_set_name(dst, "");
    CHECK(dst[0] == (char)0xAA); /* loop body never runs; caller must pre-zero */
}

static void test_sm_key_set_label_copies_and_truncates(void)
{
    char dst[SM_LABEL_MAX] = {0};
    sm_key_set_label(dst, "AUSF success");
    CHECK_STREQ(dst, "AUSF success");

    const char *too_long =
        "a label that is much longer than forty eight characters for sure";
    char dst2[SM_LABEL_MAX] = {0};
    sm_key_set_label(dst2, too_long);
    CHECK(memcmp(dst2, too_long, SM_LABEL_MAX - 1) == 0);
    CHECK(dst2[SM_LABEL_MAX - 1] == '\0');
}

/* ── sm_node_lookup ──────────────────────────────────────────────────── */

static void test_sm_node_lookup_finds_populated_node(void)
{
    mock_reset();
    mock_add_node("REG_RECEIVED", SM_KIND_NORMAL);
    mock_add_node("AUTH_FAILED", SM_KIND_FAILURE);
    mock_add_node("UE/gNB", SM_KIND_ENDPOINT);

    struct sm_node_val *v = sm_node_lookup("AUTH_FAILED");
    CHECK(v != NULL);
    if (v) CHECK(v->kind == SM_KIND_FAILURE);

    v = sm_node_lookup("UE/gNB");
    CHECK(v != NULL);
    if (v) CHECK(v->kind == SM_KIND_ENDPOINT);
}

static void test_sm_node_lookup_missing_node_returns_null(void)
{
    mock_reset();
    mock_add_node("REG_RECEIVED", SM_KIND_NORMAL);

    CHECK(sm_node_lookup("NOT_A_REAL_STATE") == NULL);
}

/* ── sm_transition_lookup ────────────────────────────────────────────── */

static void test_sm_transition_lookup_finds_valid_edge(void)
{
    mock_reset();
    mock_add_edge("NAS_AUTHENTICATING", "RES* valid", "NAS_SECURITY_PENDING");
    mock_add_edge("NAS_AUTHENTICATING", "RES* invalid", "AUTH_FAILED");

    struct sm_edge_val *e = sm_transition_lookup("NAS_AUTHENTICATING", "RES* valid");
    CHECK(e != NULL);
    if (e) CHECK_STREQ(e->to, "NAS_SECURITY_PENDING");
}

static void test_sm_transition_lookup_missing_edge_returns_null(void)
{
    mock_reset();
    mock_add_edge("NAS_AUTHENTICATING", "RES* valid", "NAS_SECURITY_PENDING");

    CHECK(sm_transition_lookup("NAS_AUTHENTICATING", "no such label") == NULL);
    CHECK(sm_transition_lookup("NO_SUCH_STATE", "RES* valid") == NULL);
}

/* Regression test for the README's "Detecting an Invalid State
 * Transition" demo: a forged/replayed Authentication Failure arriving
 * while the UE's real state has already moved on to
 * NAS_SECURITY_PENDING must NOT match, even though
 * "replay/abnormal retry" is a perfectly valid label -- just not from
 * this state. The detection is structural (composite (from,label) key),
 * not signature-based. */
static void test_sm_transition_lookup_rejects_replayed_auth_failure(void)
{
    mock_reset();
    mock_add_edge("NAS_AUTHENTICATING", "replay/abnormal retry", "REPLAY_SUSPECTED");
    mock_add_edge("NAS_SECURITY_PENDING", "integrity success", "UDM_REGISTERING");
    mock_add_edge("NAS_SECURITY_PENDING", "integrity fail", "SECURITY_FAILED");

    /* Legitimate: this edge really exists from NAS_AUTHENTICATING. */
    CHECK(sm_transition_lookup("NAS_AUTHENTICATING", "replay/abnormal retry") != NULL);

    /* Attack: same label, but the UE's real current state is
     * NAS_SECURITY_PENDING -- no such edge, must be flagged (NULL). */
    CHECK(sm_transition_lookup("NAS_SECURITY_PENDING", "replay/abnormal retry") == NULL);

    /* NAS_SECURITY_PENDING is still a perfectly valid from-state for its
     * own labels -- proves the miss above is about the (from,label) pair,
     * not NAS_SECURITY_PENDING being unreachable in the mock store. */
    CHECK(sm_transition_lookup("NAS_SECURITY_PENDING", "integrity success") != NULL);
}

/* The edge key is (from, label) -- neither alone is sufficient. Same
 * label from two different states must resolve to two different
 * destinations. */
static void test_sm_transition_lookup_disambiguates_by_composite_key(void)
{
    mock_reset();
    mock_add_edge("STATE_A", "timeout", "NF_TIMEOUT");
    mock_add_edge("STATE_B", "timeout", "CLEANUP_REQUIRED");

    struct sm_edge_val *from_a = sm_transition_lookup("STATE_A", "timeout");
    struct sm_edge_val *from_b = sm_transition_lookup("STATE_B", "timeout");

    CHECK(from_a != NULL);
    CHECK(from_b != NULL);
    if (from_a) CHECK_STREQ(from_a->to, "NF_TIMEOUT");
    if (from_b) CHECK_STREQ(from_b->to, "CLEANUP_REQUIRED");
}

int main(void)
{
    printf("test_sm_map:\n");

    RUN_TEST(test_sm_key_set_name_copies_short_string);
    RUN_TEST(test_sm_key_set_name_truncates_long_string);
    RUN_TEST(test_sm_key_set_name_empty_string);
    RUN_TEST(test_sm_key_set_label_copies_and_truncates);

    RUN_TEST(test_sm_node_lookup_finds_populated_node);
    RUN_TEST(test_sm_node_lookup_missing_node_returns_null);

    RUN_TEST(test_sm_transition_lookup_finds_valid_edge);
    RUN_TEST(test_sm_transition_lookup_missing_edge_returns_null);
    RUN_TEST(test_sm_transition_lookup_rejects_replayed_auth_failure);
    RUN_TEST(test_sm_transition_lookup_disambiguates_by_composite_key);

    return test_summary();
}
