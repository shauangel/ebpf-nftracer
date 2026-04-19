#include "smf_comm.h"

int attach_programs(struct smf_tracer_bpf *skel, const char *bin_path, pid_t pid, struct attach_target *targets, int cnt)
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