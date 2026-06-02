// namespace_tracer.c — userspace loader for namespace_tracer.bpf.c
//
// Responsibilities:
//   1. Discover free5gc NF cgroup IDs by scanning /proc.
//   2. Populate the container_cgroups BPF map.
//   3. Load and attach the BPF program via libbpf skeleton.
//   4. Poll the ring buffer and pretty-print container_context events.
//
// Build: see Makefile
// Run:   sudo ./namespace_tracer

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include "namespace_tracer.skel.h"

// ── Struct mirrors (must match namespace_tracer.bpf.c exactly) ───────────────

struct namespace_info {
    uint64_t cgroup_id;
    uint32_t pid_ns;
    uint32_t mnt_ns;
    uint32_t net_ns;
    uint32_t uts_ns;
    uint32_t ipc_ns;
    uint32_t user_ns;
    uint32_t time_ns;
};

struct container_context {
    uint32_t pid;
    uint32_t tid;
    uint32_t container_pid;
    struct namespace_info ns;
    char     comm[16];
    char     uts_nodename[65];
    uint64_t timestamp;
};

// ── Terminal colours ──────────────────────────────────────────────────────────

#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_DIM     "\033[2m"
#define COL_CYAN    "\033[36m"
#define COL_YELLOW  "\033[33m"
#define COL_GREEN   "\033[32m"
#define COL_MAGENTA "\033[35m"
#define COL_BLUE    "\033[34m"
#define COL_RED     "\033[31m"

static int use_colour = 1;

#define C(code) (use_colour ? (code) : "")

// ── NF names known to belong to free5gc ──────────────────────────────────────

static const char *nf_names[] = {
    "nrf", "amf", "smf", "udm", "ausf", "nssf", "pcf",
    NULL
};

static int is_nf_comm(const char *comm) {
    for (int i = 0; nf_names[i]; i++)
        if (strcmp(comm, nf_names[i]) == 0)
            return 1;
    return 0;
}

// ── cgroup ID discovery ───────────────────────────────────────────────────────

// On cgroupv2 the cgroup ID equals the inode number of the cgroup directory.
static uint64_t cgroup_id_from_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (uint64_t)st.st_ino;
}

// Returns the cgroupv2 directory path for a given /proc/<pid>/cgroup line.
// cgroupv2 lines have the form: "0::/<relative-path>"
static int parse_cgroupv2_path(const char *line, char *out, size_t out_len) {
    if (strncmp(line, "0::/", 4) != 0)
        return -1;
    snprintf(out, out_len, "/sys/fs/cgroup/%s", line + 4);
    // Strip trailing newline.
    size_t n = strlen(out);
    if (n > 0 && out[n - 1] == '\n')
        out[n - 1] = '\0';
    return 0;
}

// Scan /proc for processes whose comm matches a free5gc NF name.
// For each match, insert its cgroup ID into the container_cgroups BPF map.
// Returns the number of cgroup IDs successfully inserted.
static int seed_container_cgroups(struct bpf_map *map) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return 0;
    }

    // Track inserted IDs to avoid duplicates (same container, multiple threads).
    uint64_t seen[256];
    int      seen_count = 0;
    int      inserted   = 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        // Only process numeric entries (PIDs).
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        // Read /proc/<pid>/comm.
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
        FILE *f = fopen(comm_path, "r");
        if (!f)
            continue;

        char comm[32] = {};
        if (!fgets(comm, sizeof(comm), f)) {
            fclose(f);
            continue;
        }
        fclose(f);

        // Strip newline.
        comm[strcspn(comm, "\n")] = '\0';

        if (!is_nf_comm(comm))
            continue;

        // Read /proc/<pid>/cgroup and find the cgroupv2 line.
        char cgroup_path[128];
        snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%ld/cgroup", pid);
        f = fopen(cgroup_path, "r");
        if (!f)
            continue;

        char line[512];
        char dir[512] = {};
        while (fgets(line, sizeof(line), f)) {
            if (parse_cgroupv2_path(line, dir, sizeof(dir)) == 0)
                break;
        }
        fclose(f);

        if (dir[0] == '\0')
            continue;

        uint64_t cg_id = cgroup_id_from_path(dir);
        if (cg_id == 0)
            continue;

        // Skip if already seen.
        int already = 0;
        for (int i = 0; i < seen_count; i++) {
            if (seen[i] == cg_id) { already = 1; break; }
        }
        if (already)
            continue;
        if (seen_count < 256)
            seen[seen_count++] = cg_id;

        // Insert into BPF map.
        uint8_t val = 1;
        int err = bpf_map__update_elem(map, &cg_id, sizeof(cg_id),
                                       &val, sizeof(val), BPF_ANY);
        if (err) {
            fprintf(stderr, "warn: map insert cg_id=%llu (%s): %s\n",
                    (unsigned long long)cg_id, comm, strerror(-err));
            continue;
        }

        fprintf(stderr, "[seed] %-6s  pid=%-6ld  cgroup_id=%-20llu  path=%s\n",
                comm, pid, (unsigned long long)cg_id, dir);
        inserted++;
    }

    closedir(proc);
    return inserted;
}

// ── Ring buffer event handler ─────────────────────────────────────────────────

// Format a raw nanosecond kernel timestamp as HH:MM:SS.nnnnnnnnn.
static void format_ts(uint64_t ns, char *buf, size_t len) {
    uint64_t s   = ns / 1000000000ULL;
    uint64_t rem = ns % 1000000000ULL;
    unsigned hh  = (s / 3600) % 24;
    unsigned mm  = (s / 60)   % 60;
    unsigned ss  = s           % 60;
    snprintf(buf, len, "%02u:%02u:%02u.%09llu", hh, mm, ss,
             (unsigned long long)rem);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct container_context)) {
        fprintf(stderr, "warn: short event (%zu bytes)\n", data_sz);
        return 0;
    }
    const struct container_context *e = data;

    char ts[32];
    format_ts(e->timestamp, ts, sizeof(ts));

    // ── Header line ──────────────────────────────────────────────────────────
    printf("\n%s%s●%s %s%s%s%s  %s%s%s\n",
           C(COL_GREEN), C(COL_BOLD), C(COL_RESET),          // ● bullet
           C(COL_BOLD), C(COL_CYAN), e->comm, C(COL_RESET),  // NF name
           C(COL_DIM), ts, C(COL_RESET));                     // timestamp

    // ── Process identity ─────────────────────────────────────────────────────
    printf("  %sProcess%s   host_pid=%-7u  container_pid=%-7u  tid=%u\n",
           C(COL_YELLOW), C(COL_RESET),
           e->pid, e->container_pid, e->tid);

    // UTS nodename (container hostname, set by Docker to container name/ID).
    if (e->uts_nodename[0])
        printf("  %sHostname%s  %s\n",
               C(COL_YELLOW), C(COL_RESET), e->uts_nodename);

    // ── Namespace table ──────────────────────────────────────────────────────
    printf("  %sNamespaces%s\n", C(COL_YELLOW), C(COL_RESET));

    // Helper macro for each namespace row.
#define NS_ROW(label, field) \
    printf("    %-10s  %s%u%s\n", \
           (label), C(COL_MAGENTA), e->ns.field, C(COL_RESET))

    NS_ROW("cgroup",  cgroup_id);   // printed as u64 but fits in u32 for inum
    printf("    %-10s  %s%llu%s\n",
           "cgroup_id", C(COL_MAGENTA),
           (unsigned long long)e->ns.cgroup_id, C(COL_RESET));
    NS_ROW("pid",     pid_ns);
    NS_ROW("mnt",     mnt_ns);
    NS_ROW("net",     net_ns);
    NS_ROW("uts",     uts_ns);
    NS_ROW("ipc",     ipc_ns);
    NS_ROW("user",    user_ns);
    if (e->ns.time_ns)
        NS_ROW("time", time_ns);
#undef NS_ROW

    fflush(stdout);
    return 0;
}

// ── Signal handling ───────────────────────────────────────────────────────────

static volatile int stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    stop = 1;
}

// ── libbpf log callback — suppress unless verbose ─────────────────────────────

static int verbose = 0;

static int libbpf_print(enum libbpf_print_level level,
                         const char *fmt, va_list args) {
    if (!verbose && level >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    // Simple flag parsing: -v = verbose libbpf output, --no-colour = plain.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)        verbose    = 1;
        if (strcmp(argv[i], "--no-colour") == 0) use_colour = 0;
        if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [-v] [--no-colour]\n"
                   "  -v           verbose libbpf output\n"
                   "  --no-colour  plain text output\n",
                   argv[0]);
            return 0;
        }
    }

    // Disable colour when stdout is not a terminal.
    if (!isatty(STDOUT_FILENO))
        use_colour = 0;

    libbpf_set_print(libbpf_print);

    // Raise the RLIMIT_MEMLOCK limit so BPF maps can be locked in memory.
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit RLIMIT_MEMLOCK");
        return 1;
    }

    // ── Load BPF skeleton ─────────────────────────────────────────────────────
    struct namespace_tracer_bpf *skel = namespace_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "error: failed to open BPF skeleton: %s\n",
                strerror(errno));
        return 1;
    }

    int err = namespace_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "error: failed to load BPF program: %s\n",
                strerror(-err));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }

    // ── Seed container_cgroups map ────────────────────────────────────────────
    fprintf(stderr, "[*] Scanning /proc for free5gc NF processes...\n");
    int n = seed_container_cgroups(skel->maps.container_cgroups);
    if (n == 0) {
        fprintf(stderr,
                "warn: no free5gc NF cgroup IDs found — are the containers running?\n"
                "      Continuing; BPF will trace any NF container that starts now.\n");
    } else {
        fprintf(stderr, "[*] Seeded %d NF cgroup ID(s).\n", n);
    }

    // ── Attach tracepoint ─────────────────────────────────────────────────────
    err = namespace_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "error: failed to attach BPF program: %s\n",
                strerror(-err));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }
    fprintf(stderr, "[*] Tracing free5gc NF exec events. Ctrl+C to stop.\n\n");

    // ── Ring buffer ───────────────────────────────────────────────────────────
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.ns_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: ring_buffer__new: %s\n", strerror(errno));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    // ── Poll loop ─────────────────────────────────────────────────────────────
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "error: ring_buffer__poll: %s\n", strerror(-err));
            break;
        }
    }

    fprintf(stderr, "\n[*] Detaching...\n");
    ring_buffer__free(rb);
    namespace_tracer_bpf__destroy(skel);
    return 0;
}
