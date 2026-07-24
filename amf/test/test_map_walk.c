/*
 * test_map_walk.c — populates real BPF_MAP_TYPE_HASH sm_nodes/sm_edges
 * maps with the actual production FSM table (fixtures.h, mirrored from
 * amf_comm.c's sm_map_populate()) and visits every entry the same way a
 * real consumer has to: bpf_map_get_next_key() + bpf_map_lookup_elem()
 * per key. There is no "list all entries" syscall for a BPF map -- the
 * kernel only lets you ask "what key comes after this one", so that walk
 * loop (see walk_nodes()/walk_edges() below) is itself the thing under
 * test, not incidental test plumbing.
 *
 * Requires Linux + CONFIG_BPF_SYSCALL, libbpf, and root (see
 * require_root() in test_util.h).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "framework.h"
#include "test_util.h"
#include "fixtures.h"
#include "../sm_map.h"

/* ── generic hash-map walk ────────────────────────────────────────────
 * Standard kernel BPF hash-map iteration protocol: start with key=NULL,
 * each bpf_map_get_next_key() call returns the key after the one passed
 * in, and the walk ends when it returns -1/ENOENT. Each returned key is
 * then looked up separately -- get_next_key() only hands back keys, never
 * values. */

typedef void (*node_visit_fn)(const struct sm_node_key *, const struct sm_node_val *, void *);
typedef void (*edge_visit_fn)(const struct sm_edge_key *, const struct sm_edge_val *, void *);

static int walk_nodes(int fd, node_visit_fn visit, void *ctx)
{
    struct sm_node_key key, next_key;
    bool have_key = false;
    int count = 0;

    while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
        struct sm_node_val val;
        if (bpf_map_lookup_elem(fd, &next_key, &val) != 0)
            return -1; /* key vanished between get_next_key and lookup */
        visit(&next_key, &val, ctx);
        count++;
        key = next_key;
        have_key = true;
    }
    if (errno != ENOENT)
        return -1;
    return count;
}

static int walk_edges(int fd, edge_visit_fn visit, void *ctx)
{
    struct sm_edge_key key, next_key;
    bool have_key = false;
    int count = 0;

    while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
        struct sm_edge_val val;
        if (bpf_map_lookup_elem(fd, &next_key, &val) != 0)
            return -1;
        visit(&next_key, &val, ctx);
        count++;
        key = next_key;
        have_key = true;
    }
    if (errno != ENOENT)
        return -1;
    return count;
}

/* ── per-entry verification against fixtures.h ────────────────────────── */

struct node_walk_ctx {
    int mismatches;
    bool seen[FX_NODE_COUNT];
};

static void verify_node_visit(const struct sm_node_key *key, const struct sm_node_val *val, void *ctx_)
{
    struct node_walk_ctx *ctx = ctx_;
    size_t i;

    for (i = 0; i < FX_NODE_COUNT; i++)
        if (strcmp(fx_nodes[i].name, key->name) == 0)
            break;

    if (i == FX_NODE_COUNT) {
        fprintf(stderr, "    unexpected node in map: %s\n", key->name);
        ctx->mismatches++;
        return;
    }
    if (ctx->seen[i]) {
        fprintf(stderr, "    node visited more than once: %s\n", key->name);
        ctx->mismatches++;
    }
    ctx->seen[i] = true;

    if ((enum sm_node_kind)val->kind != fx_nodes[i].kind) {
        fprintf(stderr, "    node %s: kind %d, expected %d\n",
                key->name, val->kind, fx_nodes[i].kind);
        ctx->mismatches++;
    }
}

struct edge_walk_ctx {
    int mismatches;
    bool seen[FX_EDGE_COUNT];
};

static void verify_edge_visit(const struct sm_edge_key *key, const struct sm_edge_val *val, void *ctx_)
{
    struct edge_walk_ctx *ctx = ctx_;
    size_t i;

    for (i = 0; i < FX_EDGE_COUNT; i++)
        if (strcmp(fx_edges[i].from, key->from) == 0 &&
            strcmp(fx_edges[i].label, key->label) == 0)
            break;

    if (i == FX_EDGE_COUNT) {
        fprintf(stderr, "    unexpected edge in map: %s -(%s)->\n", key->from, key->label);
        ctx->mismatches++;
        return;
    }
    if (ctx->seen[i]) {
        fprintf(stderr, "    edge visited more than once: %s -(%s)->\n", key->from, key->label);
        ctx->mismatches++;
    }
    ctx->seen[i] = true;

    if (strcmp(val->to, fx_edges[i].to) != 0) {
        fprintf(stderr, "    edge %s -(%s)-> %s, expected -> %s\n",
                key->from, key->label, val->to, fx_edges[i].to);
        ctx->mismatches++;
    }
}

/* ── tests ─────────────────────────────────────────────────────────── */

static void test_walk_visits_every_populated_node_exactly_once(void)
{
    int fd = create_sm_nodes_map("test_walk_nodes");
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(fx_populate_nodes(fd) == 0);

    struct node_walk_ctx ctx = {0};
    int count = walk_nodes(fd, verify_node_visit, &ctx);

    CHECK(count == (int)FX_NODE_COUNT);
    CHECK(ctx.mismatches == 0);
    for (size_t i = 0; i < FX_NODE_COUNT; i++)
        CHECK(ctx.seen[i]);

    close(fd);
}

static void test_walk_visits_every_populated_edge_exactly_once(void)
{
    int fd = create_sm_edges_map("test_walk_edges");
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(fx_populate_edges(fd) == 0);

    struct edge_walk_ctx ctx = {0};
    int count = walk_edges(fd, verify_edge_visit, &ctx);

    CHECK(count == (int)FX_EDGE_COUNT);
    CHECK(ctx.mismatches == 0);
    for (size_t i = 0; i < FX_EDGE_COUNT; i++)
        CHECK(ctx.seen[i]);

    close(fd);
}

/* Restarting the walk (key=NULL) after a full pass must yield the same
 * count again -- guards against a walk that accidentally mutates/consumes
 * entries as it visits them. */
static void test_walk_is_repeatable(void)
{
    int fd = create_sm_nodes_map("test_walk_repeat");
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(fx_populate_nodes(fd) == 0);

    struct node_walk_ctx ctx1 = {0}, ctx2 = {0};
    int c1 = walk_nodes(fd, verify_node_visit, &ctx1);
    int c2 = walk_nodes(fd, verify_node_visit, &ctx2);

    CHECK(c1 == (int)FX_NODE_COUNT);
    CHECK(c1 == c2);

    close(fd);
}

static void test_point_lookup_known_entries(void)
{
    int nfd = create_sm_nodes_map("test_point_nodes");
    int efd = create_sm_edges_map("test_point_edges");
    CHECK(nfd >= 0 && efd >= 0);
    if (nfd < 0 || efd < 0) {
        if (nfd >= 0) close(nfd);
        if (efd >= 0) close(efd);
        return;
    }
    CHECK(fx_populate_nodes(nfd) == 0);
    CHECK(fx_populate_edges(efd) == 0);

    struct sm_node_key nkey = {};
    snprintf(nkey.name, sizeof(nkey.name), "%s", "REG_RECEIVED");
    struct sm_node_val nval = {};
    CHECK(bpf_map_lookup_elem(nfd, &nkey, &nval) == 0);
    CHECK(nval.kind == SM_KIND_NORMAL);

    struct sm_edge_key ekey = {};
    snprintf(ekey.from, sizeof(ekey.from), "%s", "UE/gNB");
    snprintf(ekey.label, sizeof(ekey.label), "%s", "InitialUEMessage");
    struct sm_edge_val eval = {};
    CHECK(bpf_map_lookup_elem(efd, &ekey, &eval) == 0);
    CHECK_STREQ(eval.to, "REG_RECEIVED");

    /* Same label as a REAL edge ("replay/abnormal retry" is valid FROM
     * NAS_AUTHENTICATING -> REPLAY_SUSPECTED), but queried from a
     * different from-state that has no such edge: the composite
     * (from,label) key must miss, not fall back to a label-only match.
     * This is the structural check the README's replay-detection demo
     * depends on. */
    struct sm_edge_key bogus = {};
    snprintf(bogus.from, sizeof(bogus.from), "%s", "NAS_SECURITY_PENDING");
    snprintf(bogus.label, sizeof(bogus.label), "%s", "replay/abnormal retry");
    struct sm_edge_val bogus_val = {};
    /* libbpf's low-level bpf_map_lookup_elem() returns -1 with errno set
     * on pre-1.0 libbpf, but returns the negative errno directly (e.g.
     * -ENOENT) on libbpf >= 1.0 -- errno is set either way (see
     * libbpf_err()), so check that instead of assuming -1. */
    CHECK(bpf_map_lookup_elem(efd, &bogus, &bogus_val) != 0 && errno == ENOENT);

    close(nfd);
    close(efd);
}

static void test_delete_elem_removed_from_walk(void)
{
    int fd = create_sm_nodes_map("test_delete_nodes");
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(fx_populate_nodes(fd) == 0);

    struct sm_node_key key = {};
    snprintf(key.name, sizeof(key.name), "%s", "REG_RECEIVED");
    CHECK(bpf_map_delete_elem(fd, &key) == 0);

    struct sm_node_val val = {};
    CHECK(bpf_map_lookup_elem(fd, &key, &val) != 0 && errno == ENOENT);

    struct node_walk_ctx ctx = {0};
    int count = walk_nodes(fd, verify_node_visit, &ctx);
    CHECK(count == (int)FX_NODE_COUNT - 1);

    close(fd);
}

int main(int argc, char **argv)
{
    require_root(argc > 0 ? argv[0] : "test_map_walk");

    printf("test_map_walk:\n");

    RUN_TEST(test_walk_visits_every_populated_node_exactly_once);
    RUN_TEST(test_walk_visits_every_populated_edge_exactly_once);
    RUN_TEST(test_walk_is_repeatable);
    RUN_TEST(test_point_lookup_known_entries);
    RUN_TEST(test_delete_elem_removed_from_walk);

    return test_summary();
}
