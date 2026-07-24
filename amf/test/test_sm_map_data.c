/*
 * test_sm_map_data.c — data-integrity tests for the REAL FSM table
 * (amf/sm_map_data.c's sm_node_data/sm_edge_data), the exact data
 * amf_comm.c's sm_map_populate() loads into the live sm_nodes/sm_edges
 * BPF maps. No mocking, no BPF shim needed here at all -- sm_map_data.c
 * has zero BPF/libbpf dependency, so it's included and linked directly.
 *
 * These checks exist because sm_nodes/sm_edges are BPF_MAP_TYPE_HASH: a
 * duplicate key silently overwrites the earlier entry, a too-long
 * name/label silently truncates via snprintf, and a dangling from/to
 * reference just means the FSM has an edge to a state that can never be
 * looked up. None of that shows up as a compile error -- only as a
 * mismatch discovered live, which is exactly what these tests replace.
 */

#include <stdio.h>
#include <string.h>

#include "../sm_map_data.h"
#include "framework.h"

static int node_exists(const char *name)
{
    for (size_t i = 0; i < sm_node_data_count; i++)
        if (strcmp(sm_node_data[i].name, name) == 0)
            return 1;
    return 0;
}

/* README.md documents this table as "23-state (+6 endpoint)" / "29 nodes,
 * 52 edges". These counts are the whole point of amf_state_machine.py
 * being the source of truth -- if either number moves, it should be
 * because someone deliberately changed the FSM (and updated the README),
 * not because an edge silently got dropped or double-added. */
static void test_node_count_matches_documented_scope(void)
{
    CHECK(sm_node_data_count == 29);
}

static void test_edge_count_matches_documented_scope(void)
{
    CHECK(sm_edge_data_count == 52);
}

static void test_node_kind_breakdown_matches_readme(void)
{
    size_t normal = 0, failure = 0, endpoint = 0;
    for (size_t i = 0; i < sm_node_data_count; i++) {
        switch (sm_node_data[i].kind) {
        case SM_KIND_NORMAL:   normal++;   break;
        case SM_KIND_FAILURE:  failure++;  break;
        case SM_KIND_ENDPOINT: endpoint++; break;
        }
    }
    CHECK(normal == 13);
    CHECK(failure == 10);
    CHECK(endpoint == 6);
    CHECK(normal + failure + endpoint == sm_node_data_count);
}

/* sm_nodes is a hash map keyed on name alone -- a duplicate name means
 * the second entry silently overwrites the first at load time. */
static void test_no_duplicate_node_names(void)
{
    for (size_t i = 0; i < sm_node_data_count; i++)
        for (size_t j = i + 1; j < sm_node_data_count; j++)
            CHECK(strcmp(sm_node_data[i].name, sm_node_data[j].name) != 0);
}

/* sm_edges is keyed on (from,label) -- same story, one level up. Two
 * edges out of the same state with the same label is not "two
 * possibilities", it's the second silently replacing the first. */
static void test_no_duplicate_edge_keys(void)
{
    for (size_t i = 0; i < sm_edge_data_count; i++) {
        for (size_t j = i + 1; j < sm_edge_data_count; j++) {
            int same_from  = strcmp(sm_edge_data[i].from,  sm_edge_data[j].from)  == 0;
            int same_label = strcmp(sm_edge_data[i].label, sm_edge_data[j].label) == 0;
            CHECK(!(same_from && same_label));
        }
    }
}

/* Every edge's from/to must resolve to a node actually declared in
 * sm_node_data -- otherwise sm_transition_lookup() can hand back a `to`
 * that sm_node_lookup() (and every uprobe/XDP caller keying off it next)
 * can never find. */
static void test_edge_endpoints_reference_real_nodes(void)
{
    for (size_t i = 0; i < sm_edge_data_count; i++) {
        CHECK(node_exists(sm_edge_data[i].from));
        CHECK(node_exists(sm_edge_data[i].to));
    }
}

/* sm_map_populate() writes these through snprintf(dst, sizeof(dst), "%s",
 * ...) -- silently truncating anything that doesn't fit SM_NAME_MAX/
 * SM_LABEL_MAX rather than erroring. A truncated name/label just means
 * two logically-different strings collide into the same key bytes. */
static void test_strings_fit_within_key_buffers(void)
{
    for (size_t i = 0; i < sm_node_data_count; i++)
        CHECK(strlen(sm_node_data[i].name) < SM_NAME_MAX);

    for (size_t i = 0; i < sm_edge_data_count; i++) {
        CHECK(strlen(sm_edge_data[i].from)  < SM_NAME_MAX);
        CHECK(strlen(sm_edge_data[i].to)    < SM_NAME_MAX);
        CHECK(strlen(sm_edge_data[i].label) < SM_LABEL_MAX);
    }
}

/* Both maps must have headroom under their BPF_MAP_TYPE_HASH
 * max_entries -- sm_map_populate() has no bounds check of its own and
 * would just start failing bpf_map__update_elem() calls past this. */
static void test_tables_fit_within_map_capacity(void)
{
    CHECK(sm_node_data_count <= SM_NODE_MAP_MAX_ENTRIES);
    CHECK(sm_edge_data_count <= SM_EDGE_MAP_MAX_ENTRIES);
}

int main(void)
{
    printf("test_sm_map_data:\n");

    RUN_TEST(test_node_count_matches_documented_scope);
    RUN_TEST(test_edge_count_matches_documented_scope);
    RUN_TEST(test_node_kind_breakdown_matches_readme);
    RUN_TEST(test_no_duplicate_node_names);
    RUN_TEST(test_no_duplicate_edge_keys);
    RUN_TEST(test_edge_endpoints_reference_real_nodes);
    RUN_TEST(test_strings_fit_within_key_buffers);
    RUN_TEST(test_tables_fit_within_map_capacity);

    return test_summary();
}
