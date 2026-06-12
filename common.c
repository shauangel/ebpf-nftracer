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


/* ── find_nf ───────────────────────────────────── */
int find_nf(const char *nf_name) {
    DIR *dp = opendir("/proc");
    if (!dp) { perror("opendir(/proc)"); return -1; }


    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {

        // scan through pid (proc file)
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        // construct process path
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        printf("path: %s\n", path);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        // get command name & check
        char comm[32] = {};
        fgets(comm, sizeof(comm), f);
        fclose(f);
        comm[strcspn(comm, "\n")] = '\0';
        if (strcmp(comm, nf_name) != 0)
            continue;
        
        // get cgroup path
        snprintf(path, sizeof(path), "/proc/%ld/cgroup", pid);
        f = fopen(path, "r");
        if (!f) continue;

        char line[512], dir[512] = {};
        while (fgets(line, sizeof(line), f))
            if (parse_cgroupv2_path(line, dir, sizeof(dir)) == 0) break;
        fclose(f);

        closedir(dp);
        return atoi(de->d_name);
    }

    closedir(dp);
    return -1;
}

/* ── get_nf_cgroup_id (new) ──────────────────────────────────────────────── */

uint64_t get_nf_cgroup_id(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "get_nf_cgroup_id: cannot open %s: %s\n",
                path, strerror(errno));
        return 0;
    }

    /* Find the cgroupv2 unified hierarchy line: "0::/<rel-path>" */
    char line[512];
    char cg_rel[480] = {};
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::/", 4) == 0) {
            strncpy(cg_rel, line + 4, sizeof(cg_rel) - 1);
            cg_rel[strcspn(cg_rel, "\n")] = '\0';
            break;
        }
    }
    fclose(f);

    if (cg_rel[0] == '\0') {
        fprintf(stderr, "get_nf_cgroup_id: no cgroupv2 entry for pid %d\n", pid);
        return 0;
    }

    /* Stat the cgroup directory — inode == cgroup_id on cgroupv2 */
    char full[512];
    snprintf(full, sizeof(full), "/sys/fs/cgroup/%s", cg_rel);

    struct stat st;
    if (stat(full, &st) != 0) {
        fprintf(stderr, "get_nf_cgroup_id: stat(%s): %s\n",
                full, strerror(errno));
        return 0;
    }

    return (uint64_t)st.st_ino;
}



