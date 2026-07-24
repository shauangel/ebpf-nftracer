#include <stdio.h>

#include "amf_comm.h"

/* ────── sm_map population (userspace state machine definitions for eBPF hash maps) ────── */

struct sm_node_def { const char *name; enum sm_node_kind kind; };

static const struct sm_node_def sm_node_data[] = {
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

static const struct sm_edge_def sm_edge_data[] = {
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

int sm_map_populate(struct amf_tracer_bpf *skel)
{
    for (size_t i = 0; i < sizeof(sm_node_data) / sizeof(sm_node_data[0]); i++) {
        struct sm_node_key key = {};
        struct sm_node_val val = {};
        snprintf(key.name, sizeof(key.name), "%s", sm_node_data[i].name);
        val.kind = (__u8)sm_node_data[i].kind;

        int err = bpf_map__update_elem(skel->maps.sm_nodes,
                                        &key, sizeof(key), &val, sizeof(val),
                                        BPF_ANY);
        if (err) {
            fprintf(stderr, "sm_map_populate: sm_nodes[%s]: %d\n",
                    sm_node_data[i].name, err);
            return err;
        }
    }

    for (size_t i = 0; i < sizeof(sm_edge_data) / sizeof(sm_edge_data[0]); i++) {
        const struct sm_edge_def *ed = &sm_edge_data[i];
        struct sm_edge_key key = {};
        struct sm_edge_val val = {};
        snprintf(key.from,  sizeof(key.from),  "%s", ed->from);
        snprintf(key.label, sizeof(key.label), "%s", ed->label);
        snprintf(val.to,    sizeof(val.to),    "%s", ed->to);

        int err = bpf_map__update_elem(skel->maps.sm_edges,
                                        &key, sizeof(key), &val, sizeof(val),
                                        BPF_ANY);
        if (err) {
            fprintf(stderr, "sm_map_populate: sm_edges[%s -> %s (%s)]: %d\n",
                    ed->from, ed->to, ed->label, err);
            return err;
        }
    }

    printf("    sm_map: %zu nodes, %zu edges loaded\n",
           sizeof(sm_node_data) / sizeof(sm_node_data[0]),
           sizeof(sm_edge_data) / sizeof(sm_edge_data[0]));
    return 0;
}

/* ────── Uprobes attach/detach ────── */

int attach_programs(struct amf_tracer_bpf *skel, const char *bin_path, pid_t pid, struct attach_target *targets, int cnt)
{
    for (int i = 0; i < cnt; i++) {

        // Initialize Option macro
        LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .func_name = targets[i].func_name,
        .retprobe = targets[i].retprobe);

        // Search for program in the skeleton
        struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, targets[i].prog_name);
        if (!prog) {
            fprintf(stderr, "failed to find program: %s\n", targets[i].prog_name);
            return -1;
        }

        // Attach program to userspace function
        targets[i].link = bpf_program__attach_uprobe_opts(prog, pid, bin_path, 0, &opts);
        if (!targets[i].link) {
            fprintf(stderr, "failed to attach to function: %s\n", targets[i].func_name);
            return -1;
        }
    }
    return 0;
}

void detach_programs(struct attach_target *targets, int cnt)
{
    for (int i = 0; i < cnt; i++) {
        if (targets[i].link) {
            bpf_link__destroy(targets[i].link);
            targets[i].link = NULL;
        }
    }
}


/* ────── Tracepoint attach/detach ────── */

int attach_tracepoints(struct amf_tracer_bpf *skel,
                       struct tp_target       *targets,
                       int                     cnt)
{
    for (int i = 0; i < cnt; i++) {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(skel->obj, targets[i].prog_name);
        if (!prog) {
            fprintf(stderr, "attach_tracepoints: program not found: %s\n",
                    targets[i].prog_name);
            return -1;
        }

        targets[i].link = bpf_program__attach_tracepoint(
            prog, targets[i].category, targets[i].name);
        if (!targets[i].link) {
            fprintf(stderr, "attach_tracepoints: failed %s/%s\n",
                    targets[i].category, targets[i].name);
            return -1;
        }
        printf("  [tp]     %s/%s\n", targets[i].category, targets[i].name);
    }
    return 0;
}

void detach_tracepoints(struct tp_target *targets, int cnt)
{
    for (int i = 0; i < cnt; i++) {
        if (targets[i].link) {
            bpf_link__destroy(targets[i].link);
            targets[i].link = NULL;
        }
    }
}