/*
 * test_map_create.c — tests that sm_map.c's two BPF_MAP_TYPE_HASH maps
 * (sm_nodes, sm_edges) can actually be created in the kernel with the
 * exact type/key/value/max_entries layout declared in sm_map.h, that
 * capacity is enforced once a map is full, and that the pin/reopen
 * mechanism sm_map.c's own top-of-file comment depends on -- amf_tracer.
 * bpf.o and amf_xdp.o both #include sm_map.c and must resolve to the SAME
 * map instance, not two independent empty copies -- actually works.
 *
 * No clang -target bpf compile of sm_map.c is involved: BPF_MAP_TYPE_HASH
 * maps are created and manipulated entirely from userspace via the bpf()
 * syscall (through libbpf's bpf_map_create()/bpf_obj_pin()/bpf_obj_get()),
 * no BPF *program* is needed for either sm_nodes or sm_edges.
 *
 * Requires Linux + CONFIG_BPF_SYSCALL, libbpf, and root (see
 * require_root() in test_util.h). The pin/reopen test additionally
 * requires bpffs mounted at /sys/fs/bpf, same requirement sm_map.c's own
 * comment notes for the production loader.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "framework.h"
#include "test_util.h"
#include "../sm_map.h"

/* ── map creation matches sm_map.h's declared layout ─────────────────── */

static void test_create_sm_nodes_map(void)
{
    int fd = create_sm_nodes_map("test_sm_nodes");
    CHECK(fd >= 0);
    if (fd < 0) {
        fprintf(stderr, "    bpf_map_create: %s\n", strerror(errno));
        return;
    }

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    CHECK(bpf_obj_get_info_by_fd(fd, &info, &len) == 0);
    CHECK(info.type == BPF_MAP_TYPE_HASH);
    CHECK(info.key_size == sizeof(struct sm_node_key));
    CHECK(info.value_size == sizeof(struct sm_node_val));
    CHECK(info.max_entries == SM_NODE_MAP_MAX_ENTRIES);

    close(fd);
}

static void test_create_sm_edges_map(void)
{
    int fd = create_sm_edges_map("test_sm_edges");
    CHECK(fd >= 0);
    if (fd < 0) {
        fprintf(stderr, "    bpf_map_create: %s\n", strerror(errno));
        return;
    }

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    CHECK(bpf_obj_get_info_by_fd(fd, &info, &len) == 0);
    CHECK(info.type == BPF_MAP_TYPE_HASH);
    CHECK(info.key_size == sizeof(struct sm_edge_key));
    CHECK(info.value_size == sizeof(struct sm_edge_val));
    CHECK(info.max_entries == SM_EDGE_MAP_MAX_ENTRIES);

    close(fd);
}

/* Two separately-created (unpinned) maps must NOT alias each other --
 * guards against a test helper bug that would make every other test in
 * this suite pass against a single accidentally-shared fd. */
static void test_independent_creations_are_distinct_maps(void)
{
    int fd1 = create_sm_nodes_map("test_sm_nodes_a");
    int fd2 = create_sm_nodes_map("test_sm_nodes_b");
    CHECK(fd1 >= 0 && fd2 >= 0);
    if (fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        return;
    }

    struct sm_node_key key = {};
    struct sm_node_val val = { .kind = SM_KIND_NORMAL };
    snprintf(key.name, sizeof(key.name), "%s", "ONLY_IN_A");
    CHECK(bpf_map_update_elem(fd1, &key, &val, BPF_ANY) == 0);

    struct sm_node_val out = {};
    CHECK(bpf_map_lookup_elem(fd1, &key, &out) == 0);
    CHECK(bpf_map_lookup_elem(fd2, &key, &out) == -1 && errno == ENOENT);

    close(fd1);
    close(fd2);
}

/* ── capacity enforcement (SM_NODE_MAP_MAX_ENTRIES) ──────────────────── */

static void test_map_rejects_insert_past_max_entries(void)
{
    int fd = create_sm_nodes_map("test_sm_nodes_full");
    CHECK(fd >= 0);
    if (fd < 0) return;

    for (int i = 0; i < SM_NODE_MAP_MAX_ENTRIES; i++) {
        struct sm_node_key key = {};
        struct sm_node_val val = { .kind = SM_KIND_NORMAL };
        snprintf(key.name, sizeof(key.name), "NODE_%d", i);
        CHECK(bpf_map_update_elem(fd, &key, &val, BPF_ANY) == 0);
    }

    /* A further, DISTINCT key past capacity must fail. */
    struct sm_node_key overflow_key = {};
    struct sm_node_val val = { .kind = SM_KIND_NORMAL };
    snprintf(overflow_key.name, sizeof(overflow_key.name), "%s", "ONE_TOO_MANY");
    CHECK(bpf_map_update_elem(fd, &overflow_key, &val, BPF_ANY) != 0);
    CHECK(errno == E2BIG || errno == ENOSPC);

    /* Re-updating an EXISTING key while the map is full must still
     * succeed -- capacity is on distinct keys, not on writes. */
    struct sm_node_key existing_key = {};
    snprintf(existing_key.name, sizeof(existing_key.name), "%s", "NODE_0");
    val.kind = SM_KIND_FAILURE;
    CHECK(bpf_map_update_elem(fd, &existing_key, &val, BPF_ANY) == 0);

    close(fd);
}

/* ── pinning: the actual mechanism sm_map.c relies on to share sm_nodes/
 * sm_edges between amf_tracer.bpf.o and amf_xdp.o ──────────────────────
 * Uses a test-local pin path so this never collides with a real running
 * loader's /sys/fs/bpf/sm_nodes. */

#define TEST_PIN_PATH "/sys/fs/bpf/amf_test_sm_nodes_pin"

static void test_pin_and_reopen_resolve_to_same_map(void)
{
    unlink(TEST_PIN_PATH); /* clean slate if a previous run was interrupted */

    int fd1 = create_sm_nodes_map("test_sm_nodes_pin");
    CHECK(fd1 >= 0);
    if (fd1 < 0) return;

    if (bpf_obj_pin(fd1, TEST_PIN_PATH) != 0) {
        fprintf(stderr,
                "    bpf_obj_pin(%s): %s (is bpffs mounted at /sys/fs/bpf?)\n",
                TEST_PIN_PATH, strerror(errno));
        CHECK(0);
        close(fd1);
        return;
    }

    struct sm_node_key key = {};
    struct sm_node_val val = { .kind = SM_KIND_ENDPOINT };
    snprintf(key.name, sizeof(key.name), "%s", "PINNED_PROBE");
    CHECK(bpf_map_update_elem(fd1, &key, &val, BPF_ANY) == 0);

    /* A second, independent open of the pin path stands in for amf_xdp.o
     * opening the SAME pinned map that amf_tracer.bpf.o's loader already
     * created and populated -- it must see the write made through fd1. */
    int fd2 = bpf_obj_get(TEST_PIN_PATH);
    CHECK(fd2 >= 0);
    if (fd2 >= 0) {
        struct sm_node_val out = {};
        CHECK(bpf_map_lookup_elem(fd2, &key, &out) == 0);
        CHECK(out.kind == SM_KIND_ENDPOINT);
        close(fd2);
    }

    close(fd1);
    unlink(TEST_PIN_PATH);
}

int main(int argc, char **argv)
{
    require_root(argc > 0 ? argv[0] : "test_map_create");

    printf("test_map_create:\n");

    RUN_TEST(test_create_sm_nodes_map);
    RUN_TEST(test_create_sm_edges_map);
    RUN_TEST(test_independent_creations_are_distinct_maps);
    RUN_TEST(test_map_rejects_insert_past_max_entries);
    RUN_TEST(test_pin_and_reopen_resolve_to_same_map);

    return test_summary();
}
