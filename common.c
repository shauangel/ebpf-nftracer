#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "common.h"

// ── cgroup discovery ───────────────────────

static uint64_t cgroup_id_from_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (uint64_t)st.st_ino;
}

static int parse_cgroupv2_path(const char *line, char *out, size_t out_len) {
    if (strncmp(line, "0::/", 4) != 0)
        return -1;
    snprintf(out, out_len, "/sys/fs/cgroup/%s", line + 4);
    size_t n = strlen(out);
    if (n > 0 && out[n - 1] == '\n')
        out[n - 1] = '\0';
    return 0;
}

uint64_t get_nf_cgroup_id(pid_t pid) {
    // get cgroup path
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512], dir[512] = {};
    while (fgets(line, sizeof(line), f))
        if (parse_cgroupv2_path(line, dir, sizeof(dir)) == 0) break;
    fclose(f);
    if (dir[0] == '\0') return 0;

    uint64_t cg_id = cgroup_id_from_path(dir);
    if (cg_id == 0) return 0;
    // printf("cgroup path: %s\n", dir);
    // printf("cgroup id: %llu\n", (unsigned long long)cg_id);
    return cg_id;
}

/* TODO: multiple nf support (same specific type of nf) */
/* ── find_nf (single nf) ───────────────────────────────────── */
int find_nf(const char *nf_name) {
    DIR *dp = opendir("/proc");
    if (!dp) { perror("opendir(/proc)"); return -1; }
    struct dirent *de;

    // scan through pid (proc file)
    while ((de = readdir(dp)) != NULL) {
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        // construct process path
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        // get command name & check
        char comm[32] = {};
        fgets(comm, sizeof(comm), f);
        fclose(f);
        comm[strcspn(comm, "\n")] = '\0';
        if (strcmp(comm, nf_name) != 0)
            continue;
        // printf("path: %s\n", path);

        // stop if find one
        closedir(dp);
        return atoi(de->d_name);
    }

    closedir(dp);
    return -1;
}



