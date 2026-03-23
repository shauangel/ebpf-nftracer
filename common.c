#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

static int is_pid_dir(const char *name)
{
    for (int i = 0; name[i]; i++) {
        if (!isdigit((unsigned char)name[i]))
            return 0;
    }
    return name[0] != '\0';
}

static int looks_like_nf_cmdline(const char *cmdline, const char *nf_name)
{
    char pattern1[64];
    char pattern2[64];
    char pattern3[128];

    snprintf(pattern1, sizeof(pattern1), "./bin/%s", nf_name);
    snprintf(pattern2, sizeof(pattern2), "/bin/%s", nf_name);
    snprintf(pattern3, sizeof(pattern3), "free5gc/bin/%s", nf_name);

    return strstr(cmdline, pattern1) ||
           strstr(cmdline, pattern2) ||
           strstr(cmdline, pattern3);
}

int find_nf_exe(const char *nf_name, char *exe_path, size_t exe_path_sz)
{
    DIR *dp = opendir("/proc");
    struct dirent *de;

    if (!dp) {
        perror("opendir(/proc)");
        return -1;
    }

    while ((de = readdir(dp)) != NULL) {
        char cmdline_path[PATH_MAX];
        char proc_exe_path[PATH_MAX];
        char cmdline[4096];
        FILE *f;
        size_t nread;
        ssize_t llen;

        if (!is_pid_dir(de->d_name))
            continue;

        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", de->d_name);
        f = fopen(cmdline_path, "rb");
        if (!f)
            continue;

        nread = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);

        if (nread == 0)
            continue;

        cmdline[nread] = '\0';

        if (!looks_like_nf_cmdline(cmdline, nf_name))
            continue;

        snprintf(proc_exe_path, sizeof(proc_exe_path), "/proc/%s/exe", de->d_name);
        llen = readlink(proc_exe_path, exe_path, exe_path_sz - 1);
        if (llen < 0)
            continue;

        exe_path[llen] = '\0';
        closedir(dp);
        return atoi(de->d_name);
    }

    closedir(dp);
    return -1;
}