#ifndef AMF_TEST_FIXTURES_H
#define AMF_TEST_FIXTURES_H

/*
 * fixtures.h — the REAL 29-node/52-edge threat-aware AMF FSM table,
 * mirrored 1:1 from amf_comm.c's sm_node_data[]/sm_edge_data[] (itself
 * mirrored from amf/amf_state_machine.py -- see amf_comm.c's own comment
 * on keeping the two in sync by inspection). Testing map creation/walking
 * against this exact table, rather than a handful of hand-picked entries,
 * is what would actually catch a regression like the table growing past
 * SM_NODE_MAP_MAX_ENTRIES/SM_EDGE_MAP_MAX_ENTRIES (see
 * test_map_create.c's capacity test).
 *
 * Keep in sync with amf_comm.c's sm_node_data[]/sm_edge_data[] by
 * inspection, same convention amf_comm.c itself uses for
 * amf_state_machine.py.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>

#include "../sm_map.h"

struct sm_node_def { const char *name; enum sm_node_kind kind; };

static const struct sm_node_def fx_nodes[] = {
    { "REG_RECEIVED",             SM_KIND_NORMAL },
    { "CONTEXT_LOOKUP",           SM_KIND_NORMAL },
    { "IDENTITY_PENDING",         SM_KIND_NORMAL },
    { "AUTH_VECTOR_PENDING",      SM_KIND_NORMAL },
    { "NAS_AUTHENTICATING",       SM_KIND_NORMAL },
    { "NAS_SECURITY_PENDING",     SM_KIND_NORMAL },
    { "UDM_REGISTERING",          SM_KIND_NORMAL },
    { "SUBSCRIPTION_LOADING",     SM_KIND_NORMAL },
    { "POLICY_ASSOCIATING",       SM_KIND_NORMAL },
    { "UE_CONTEXT_READY",         SM_KIND_NORMAL },
    { "SM_CONTEXT_PENDING",       SM_KIND_NORMAL },
    { "INITIAL_CONTEXT_SETUP",    SM_KIND_NORMAL },
    { "REGISTERED_CONNECTED",     SM_KIND_NORMAL },

    { "REG_REJECTED",             SM_KIND_FAILURE },
    { "AUTH_FAILED",              SM_KIND_FAILURE },
    { "REPLAY_SUSPECTED",         SM_KIND_FAILURE },
    { "SECURITY_FAILED",          SM_KIND_FAILURE },
    { "SECURITY_POLICY_VIOLATION",SM_KIND_FAILURE },
    { "NF_TIMEOUT",               SM_KIND_FAILURE },
    { "SLICE_REJECTED",           SM_KIND_FAILURE },
    { "PDU_SESSION_REJECTED",     SM_KIND_FAILURE },
    { "CONTEXT_SETUP_FAILED",     SM_KIND_FAILURE },
    { "CLEANUP_REQUIRED",         SM_KIND_FAILURE },

    { "UE/gNB", SM_KIND_ENDPOINT },
    { "AMF",    SM_KIND_ENDPOINT },
    { "AUSF",   SM_KIND_ENDPOINT },
    { "UDM",    SM_KIND_ENDPOINT },
    { "PCF",    SM_KIND_ENDPOINT },
    { "SMF",    SM_KIND_ENDPOINT },
};

struct sm_edge_def { const char *from, *to, *label; };

static const struct sm_edge_def fx_edges[] = {
    { "UE/gNB",                "REG_RECEIVED",           "InitialUEMessage" },
    { "REG_RECEIVED",          "CONTEXT_LOOKUP",         "valid NAS" },
    { "REG_RECEIVED",          "REG_REJECTED",           "invalid NAS" },
    { "CONTEXT_LOOKUP",        "AMF",                    "Namf ContextTransfer" },
    { "AMF",                   "CONTEXT_LOOKUP",         "response" },
    { "CONTEXT_LOOKUP",        "IDENTITY_PENDING",       "context unavailable" },
    { "IDENTITY_PENDING",      "UE/gNB",                 "Request identity" },
    { "UE/gNB",                "IDENTITY_PENDING",       "Response identity" },
    { "IDENTITY_PENDING",      "AUTH_VECTOR_PENDING",    "identity available" },
    { "AUTH_VECTOR_PENDING",   "AUSF",                   "Nausf Authentication" },
    { "AUSF",                  "AUTH_VECTOR_PENDING",    "auth vector response" },
    { "AUTH_VECTOR_PENDING",   "NAS_AUTHENTICATING",     "AUSF success" },
    { "AUTH_VECTOR_PENDING",   "AUTH_FAILED",            "AUSF reject" },
    { "AUTH_VECTOR_PENDING",   "NF_TIMEOUT",             "timeout" },
    { "NAS_AUTHENTICATING",    "UE/gNB",                 "NAS Authentication" },
    { "NAS_AUTHENTICATING",    "NAS_SECURITY_PENDING",   "RES* valid" },
    { "NAS_AUTHENTICATING",    "AUTH_FAILED",            "RES* invalid" },
    { "NAS_AUTHENTICATING",    "REPLAY_SUSPECTED",       "replay/abnormal retry" },
    { "NAS_SECURITY_PENDING",  "UE/gNB",                 "Security Mode Command" },
    { "UE/gNB",                "NAS_SECURITY_PENDING",   "Security Mode Complete" },
    { "NAS_SECURITY_PENDING",  "UDM_REGISTERING",        "integrity success" },
    { "NAS_SECURITY_PENDING",  "SECURITY_FAILED",        "integrity fail" },
    { "NAS_SECURITY_PENDING",  "SECURITY_POLICY_VIOLATION", "NULL/invalid algorithm" },
    { "UDM_REGISTERING",       "UDM",                    "Nudm UECM Registration" },
    { "UDM",                   "UDM_REGISTERING",        "registration response" },
    { "UDM_REGISTERING",       "SUBSCRIPTION_LOADING",   "success" },
    { "UDM_REGISTERING",       "REG_REJECTED",           "UDM reject" },
    { "UDM_REGISTERING",       "NF_TIMEOUT",             "timeout" },
    { "SUBSCRIPTION_LOADING",  "UDM",                    "Nudm SDM Get" },
    { "UDM",                   "SUBSCRIPTION_LOADING",   "subscription data" },
    { "SUBSCRIPTION_LOADING",  "POLICY_ASSOCIATING",     "valid subscription" },
    { "SUBSCRIPTION_LOADING",  "SLICE_REJECTED",         "invalid S-NSSAI" },
    { "POLICY_ASSOCIATING",    "PCF",                    "Npcf AM Policy Create" },
    { "PCF",                   "POLICY_ASSOCIATING",     "policy response" },
    { "POLICY_ASSOCIATING",    "UE_CONTEXT_READY",       "policy success" },
    { "POLICY_ASSOCIATING",    "REG_REJECTED",           "policy reject" },
    { "POLICY_ASSOCIATING",    "NF_TIMEOUT",             "timeout" },
    { "UE_CONTEXT_READY",      "SM_CONTEXT_PENDING",     "PDU session request" },
    { "SM_CONTEXT_PENDING",    "SMF",                    "Nsmf Create/Update SM Context" },
    { "SMF",                   "SM_CONTEXT_PENDING",     "SM context response" },
    { "SM_CONTEXT_PENDING",    "INITIAL_CONTEXT_SETUP",  "SMF success" },
    { "SM_CONTEXT_PENDING",    "PDU_SESSION_REJECTED",   "SMF reject" },
    { "SM_CONTEXT_PENDING",    "SLICE_REJECTED",         "slice validation failure" },
    { "INITIAL_CONTEXT_SETUP", "UE/gNB",                 "InitialContextSetupRequest" },
    { "UE/gNB",                "INITIAL_CONTEXT_SETUP",  "setup response" },
    { "INITIAL_CONTEXT_SETUP", "REGISTERED_CONNECTED",   "setup success" },
    { "INITIAL_CONTEXT_SETUP", "CONTEXT_SETUP_FAILED",   "setup failure" },
    { "AUTH_FAILED",           "CLEANUP_REQUIRED",       "release partial context" },
    { "SECURITY_FAILED",       "CLEANUP_REQUIRED",       "release partial context" },
    { "REG_REJECTED",          "CLEANUP_REQUIRED",       "cleanup" },
    { "PDU_SESSION_REJECTED",  "UE_CONTEXT_READY",       "retain UE context" },
    { "CONTEXT_SETUP_FAILED",  "CLEANUP_REQUIRED",       "release resources" },
};

#define FX_NODE_COUNT (sizeof(fx_nodes) / sizeof(fx_nodes[0]))
#define FX_EDGE_COUNT (sizeof(fx_edges) / sizeof(fx_edges[0]))

static inline const struct sm_node_def *fx_find_node(const char *name)
{
    for (size_t i = 0; i < FX_NODE_COUNT; i++)
        if (strcmp(fx_nodes[i].name, name) == 0)
            return &fx_nodes[i];
    return NULL;
}

/* Load every fx_nodes[] entry into a real sm_nodes map fd, exactly the
 * way amf_comm.c's sm_map_populate() loads it into the production
 * skeleton's map -- snprintf into a zero-initialized key, then
 * bpf_map_update_elem(). Returns 0 on success, the first non-zero
 * bpf_map_update_elem() return value otherwise. */
static inline int fx_populate_nodes(int fd)
{
    for (size_t i = 0; i < FX_NODE_COUNT; i++) {
        struct sm_node_key key = {};
        struct sm_node_val val = {};
        snprintf(key.name, sizeof(key.name), "%s", fx_nodes[i].name);
        val.kind = (__u8)fx_nodes[i].kind;

        int err = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
        if (err)
            return err;
    }
    return 0;
}

static inline int fx_populate_edges(int fd)
{
    for (size_t i = 0; i < FX_EDGE_COUNT; i++) {
        const struct sm_edge_def *ed = &fx_edges[i];
        struct sm_edge_key key = {};
        struct sm_edge_val val = {};
        snprintf(key.from,  sizeof(key.from),  "%s", ed->from);
        snprintf(key.label, sizeof(key.label), "%s", ed->label);
        snprintf(val.to,    sizeof(val.to),    "%s", ed->to);

        int err = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
        if (err)
            return err;
    }
    return 0;
}

#endif /* AMF_TEST_FIXTURES_H */
