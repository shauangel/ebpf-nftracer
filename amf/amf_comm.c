#include <stdio.h>

#include "amf_comm.h"
#include "sm_map_data.h"

/* ── sm_map population (userspace side of sm_map.c's BPF hash maps) ──────
 * Node/edge data lives in sm_map_data.c (sm_node_data/sm_edge_data,
 * shared with amf/test/'s unit tests) -- see sm_map_data.h. */

int sm_map_populate(struct amf_tracer_bpf *skel)
{
    for (size_t i = 0; i < sm_node_data_count; i++) {
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

    for (size_t i = 0; i < sm_edge_data_count; i++) {
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
           sm_node_data_count, sm_edge_data_count);
    return 0;
}

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


/* ── Tracepoint attach / detach (new) ───────────────────────────────────── */

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