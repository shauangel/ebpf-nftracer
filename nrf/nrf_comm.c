#include <stdio.h>
#include "nrf_comm.h"

/* ── Uprobe attach / detach (original, unchanged) ───────────────────────── */

int attach_programs(struct nrf_tracer_bpf *skel,
                    const char            *bin_path,
                    pid_t                  pid,
                    struct attach_target  *targets,
                    int                    cnt)
{
    for (int i = 0; i < cnt; i++) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .func_name = targets[i].func_name,
            .retprobe  = targets[i].retprobe);

        struct bpf_program *prog =
            bpf_object__find_program_by_name(skel->obj, targets[i].prog_name);
        if (!prog) {
            fprintf(stderr, "attach_programs: program not found: %s\n",
                    targets[i].prog_name);
            return -1;
        }

        targets[i].link = bpf_program__attach_uprobe_opts(
            prog, pid, bin_path, 0, &opts);
        if (!targets[i].link) {
            fprintf(stderr, "attach_programs: failed to attach %s → %s\n",
                    targets[i].prog_name, targets[i].func_name);
            return -1;
        }
        printf("  [uprobe] %-28s  %s\n",
               targets[i].prog_name, targets[i].func_name);
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

int attach_tracepoints(struct nrf_tracer_bpf *skel,
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
