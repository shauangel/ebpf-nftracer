// namespace_tracer.c — userspace loader for socket-level NF communication tracing.
//
// Kept from previous version:
//   - /proc-based cgroup ID discovery (container_cgroups map population)
//   - libbpf skeleton load/attach pattern
//
// Updated:
//   - Event struct mirrors the new comm_event (connect/accept/sendmsg/recvmsg)
//   - Display shows connection flow: "amf → nrf  10.100.0.20:8000"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include "namespace_tracer.skel.h"

// ── Event struct mirror (must match namespace_tracer.bpf.c exactly) ──────────

#define EVT_CONNECT  1
#define EVT_ACCEPT   2
#define EVT_SENDMSG  3
#define EVT_RECVMSG  4

struct comm_event {
    uint64_t ts_ns;
    uint64_t cgroup_id;
    uint32_t pid;
    uint32_t tid;
    uint8_t  event_type;
    uint8_t  af;
    uint8_t  pad[2];
    uint32_t saddr[4];
    uint32_t daddr[4];
    uint16_t sport;
    uint16_t dport;
    int64_t  ret;
    uint64_t bytes;
    char     comm[16];
};

// ── Colour helpers ────────────────────────────────────────────────────────────

#define COL_RESET    "\033[0m"
#define COL_BOLD     "\033[1m"
#define COL_DIM      "\033[2m"
#define COL_RED      "\033[31m"
#define COL_GREEN    "\033[32m"
#define COL_YELLOW   "\033[33m"
#define COL_BLUE     "\033[34m"
#define COL_MAGENTA  "\033[35m"
#define COL_CYAN     "\033[36m"
#define COL_WHITE    "\033[37m"

static int use_colour = 1;
#define C(x) (use_colour ? (x) : "")

// ── free5gc NF comm names ─────────────────────────────────────────────────────

static const char *nf_names[] = {
    "nrf", "amf", "smf", "udm", "ausf", "nssf", "pcf", NULL
};

static int is_nf_comm(const char *comm) {
    for (int i = 0; nf_names[i]; i++)
        if (strcmp(comm, nf_names[i]) == 0)
            return 1;
    return 0;
}

// ── cgroup discovery (unchanged from previous version) ───────────────────────

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

static int seed_container_cgroups(struct bpf_map *map) {
    DIR *proc = opendir("/proc");
    if (!proc) { perror("opendir /proc"); return 0; }

    uint64_t seen[256];
    int      seen_count = 0;
    int      inserted   = 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char comm[32] = {};
        fgets(comm, sizeof(comm), f);
        fclose(f);
        comm[strcspn(comm, "\n")] = '\0';

        if (!is_nf_comm(comm))
            continue;

        snprintf(path, sizeof(path), "/proc/%ld/cgroup", pid);
        f = fopen(path, "r");
        if (!f) continue;

        char line[512], dir[512] = {};
        while (fgets(line, sizeof(line), f))
            if (parse_cgroupv2_path(line, dir, sizeof(dir)) == 0) break;
        fclose(f);

        if (dir[0] == '\0') continue;

        uint64_t cg_id = cgroup_id_from_path(dir);
        if (cg_id == 0) continue;

        int already = 0;
        for (int i = 0; i < seen_count; i++)
            if (seen[i] == cg_id) { already = 1; break; }
        if (already) continue;
        if (seen_count < 256) seen[seen_count++] = cg_id;

        uint8_t val = 1;
        int err = bpf_map__update_elem(map, &cg_id, sizeof(cg_id),
                                       &val, sizeof(val), BPF_ANY);
        if (err) {
            fprintf(stderr, "warn: map insert cg_id=%llu (%s): %s\n",
                    (unsigned long long)cg_id, comm, strerror(-err));
            continue;
        }
        fprintf(stderr, "  [seed] %-6s  cgroup_id=%-20llu  %s\n",
                comm, (unsigned long long)cg_id, dir);
        inserted++;
    }

    closedir(proc);
    return inserted;
}

// ── Address formatting ────────────────────────────────────────────────────────

static void fmt_addr(uint8_t af, const uint32_t *addr, uint16_t port,
                     char *buf, size_t len) {
    char ip[INET6_ADDRSTRLEN] = {};
    if (af == 2 /* AF_INET */) {
        inet_ntop(AF_INET, addr, ip, sizeof(ip));
    } else if (af == 10 /* AF_INET6 */) {
        inet_ntop(AF_INET6, addr, ip, sizeof(ip));
    } else {
        snprintf(ip, sizeof(ip), "?");
    }
    if (port)
        snprintf(buf, len, "%s:%u", ip, port);
    else
        snprintf(buf, len, "%s", ip);
}

// ── Timestamp ─────────────────────────────────────────────────────────────────

static void fmt_ts(uint64_t ns, char *buf, size_t len) {
    uint64_t s   = ns / 1000000000ULL;
    uint64_t rem = ns % 1000000000ULL;
    snprintf(buf, len, "%02u:%02u:%02u.%06llu",
             (unsigned)(s / 3600) % 24,
             (unsigned)(s / 60)   % 60,
             (unsigned) s         % 60,
             (unsigned long long)(rem / 1000));  // microseconds
}

// ── Per-NF colour (consistent across all events for one service) ──────────────

static const char *nf_colour(const char *comm) {
    static const struct { const char *name; const char *col; } map[] = {
        { "nrf",  COL_CYAN    },
        { "amf",  COL_GREEN   },
        { "smf",  COL_YELLOW  },
        { "udm",  COL_BLUE    },
        { "ausf", COL_MAGENTA },
        { "nssf", COL_RED     },
        { "pcf",  COL_WHITE   },
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(*map); i++)
        if (strcmp(comm, map[i].name) == 0)
            return map[i].col;
    return COL_WHITE;
}

// ── Ring buffer event handler ─────────────────────────────────────────────────

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct comm_event)) {
        fprintf(stderr, "warn: short event (%zu bytes)\n", data_sz);
        return 0;
    }
    const struct comm_event *e = data;

    char ts[24];
    fmt_ts(e->ts_ns, ts, sizeof(ts));

    const char *col = nf_colour(e->comm);

    // ── Connection events (CONNECT / ACCEPT) ──────────────────────────────────
    if (e->event_type == EVT_CONNECT || e->event_type == EVT_ACCEPT) {
        char remote[64] = {};
        fmt_addr(e->af, e->daddr, e->dport, remote, sizeof(remote));

        const char *arrow = (e->event_type == EVT_CONNECT) ? "→" : "←";
        const char *label = (e->event_type == EVT_CONNECT) ? "CONNECT" : "ACCEPT ";

        printf("%s%s%s  %s%s%s%-5s%s  %s %s%s%s  pid=%-6u  cg=%llu\n",
               C(COL_DIM), ts, C(COL_RESET),
               C(COL_BOLD), C(col), e->comm, C(COL_RESET),
               C(COL_DIM),
               arrow,
               C(COL_BOLD), remote, C(COL_RESET),
               e->pid,
               (unsigned long long)e->cgroup_id);

        // Indent the event label below for readability.
        printf("  %s%s%s\n", C(COL_DIM), label, C(COL_RESET));

    // ── Data events (SENDMSG / RECVMSG) ──────────────────────────────────────
    } else if (e->event_type == EVT_SENDMSG || e->event_type == EVT_RECVMSG) {
        const char *arrow = (e->event_type == EVT_SENDMSG) ? "↑" : "↓";
        const char *label = (e->event_type == EVT_SENDMSG) ? "SEND" : "RECV";
        const char *dcol  = (e->event_type == EVT_SENDMSG) ? COL_YELLOW : COL_BLUE;

        printf("%s%s%s  %s%s%s%-5s%s  %s%s%s  %s%llu bytes%s  pid=%u\n",
               C(COL_DIM), ts, C(COL_RESET),
               C(COL_BOLD), C(col), e->comm, C(COL_RESET),
               C(COL_DIM),
               arrow,
               C(COL_BOLD), C(dcol), label, C(COL_RESET),
               C(COL_BOLD), (unsigned long long)e->bytes, C(COL_RESET),
               e->pid);
    }

    fflush(stdout);
    return 0;
}

// ── Signal + libbpf boilerplate ───────────────────────────────────────────────

static volatile int stop = 0;
static void         sig_handler(int sig) { (void)sig; stop = 1; }

static int verbose = 0;
static int libbpf_print(enum libbpf_print_level level,
                         const char *fmt, va_list args) {
    if (!verbose && level >= LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v")          == 0) verbose    = 1;
        if (strcmp(argv[i], "--no-colour") == 0) use_colour = 0;
        if (strcmp(argv[i], "-h")          == 0) {
            printf("Usage: %s [-v] [--no-colour]\n"
                   "  -v           verbose libbpf output\n"
                   "  --no-colour  plain text (for log files)\n",
                   argv[0]);
            return 0;
        }
    }
    if (!isatty(STDOUT_FILENO))
        use_colour = 0;

    libbpf_set_print(libbpf_print);

    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit"); return 1;
    }

    // Load BPF skeleton.
    struct namespace_tracer_bpf *skel = namespace_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "error: open skeleton: %s\n", strerror(errno));
        return 1;
    }
    int err = namespace_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "error: load BPF: %s\n", strerror(-err));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }

    // Seed cgroup filter map (unchanged logic from previous version).
    fprintf(stderr, "[*] Scanning /proc for free5gc NF processes...\n");
    int n = seed_container_cgroups(skel->maps.container_cgroups);
    if (n == 0)
        fprintf(stderr, "warn: no NF cgroup IDs found — are containers running?\n");
    else
        fprintf(stderr, "[*] Seeded %d NF cgroup(s). Attaching probes...\n\n", n);

    // Attach all tracepoints.
    err = namespace_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "error: attach: %s\n", strerror(-err));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }

    // Print column header.
    printf("%sTIMESTAMP       NF       DIR  REMOTE / BYTES"
           "                     PID%s\n",
           C(COL_BOLD), C(COL_RESET));
    printf("%s%.*s%s\n", C(COL_DIM), 72, "────────────────────────────────"
           "────────────────────────────────────────", C(COL_RESET));

    // Ring buffer.
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.comm_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: ring_buffer__new: %s\n", strerror(errno));
        namespace_tracer_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    fprintf(stderr, "[*] Tracing. Ctrl+C to stop.\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "error: poll: %s\n", strerror(-err));
            break;
        }
    }

    fprintf(stderr, "\n[*] Detaching.\n");
    ring_buffer__free(rb);
    namespace_tracer_bpf__destroy(skel);
    return 0;
}
