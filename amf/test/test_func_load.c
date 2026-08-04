/* Must come before any #include: same _GNU_SOURCE requirement as
 * ../test_xdp.c -- localtime_r()/strtok_r() live behind it on glibc. */
#define _GNU_SOURCE

/*
 * test_func_load.c — loader for ../amf_func_load.bpf.c: attaches every
 * uprobe declared in ../amf_func_hooks.c (ngap_hook_funcs[], nas_hook_funcs[],
 * sbi_hook_funcs[]) against a running AMF process, then prints every event
 * that lands in the shared "events" ringbuf, decoded per
 * ../amf_func_load_events.h.
 *
 * This is a THIRD kind of test binary in this directory, next to the
 * BPF_MAP_TYPE_HASH tests (test_map_create/test_map_walk/sm_use_case) and
 * the XDP watchdog (test_xdp): a live uprobe attach + ringbuf drain, the
 * same shape ../amf_loader.c uses for the (separate, older) amf_tracer.bpf.c
 * skeleton. This file does NOT reuse amf_comm.c's attach_programs()/
 * detach_programs() -- those are hardcoded to `struct amf_tracer_bpf *`
 * (bpftool-generated skeleton type for the OLD amf_tracer.bpf.c), and
 * amf_func_load.bpf.c intentionally has no generated skeleton of its own
 * (see its own file header: the loader resolves attach_target[].func_name
 * itself via bpf_object__find_program_by_name(), not a typed skeleton
 * accessor). attach_targets()/detach_targets() below are the same logic,
 * just generic over `struct bpf_object *`.
 *
 * Deliberately continue-on-error while attaching (see attach_targets()):
 * unlike a production loader, the point of THIS run is to find out exactly
 * which of the 20 targets resolve against the real, currently-running AMF
 * binary on kernel 6.14 -- amf_func_load.bpf.c's own header comment already
 * flags that hand-derived Go struct offsets have no compiler to catch a
 * dependency-version mismatch; a symbol that fails to resolve is the same
 * kind of thing surfacing at attach time instead, and aborting on the
 * first one would hide how many of the rest still work.
 *
 * Requires Linux, libbpf with bpf_program__attach_uprobe_opts() (libbpf
 * >= 0.7), and root (CAP_BPF at minimum -- uprobes don't need
 * CAP_NET_ADMIN the way test_xdp.c's XDP attach does).
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>

#include <bpf/libbpf.h>

#include "../../common.h"             /* struct attach_target, find_nf() */
#include "../amf_func_load_events.h"  /* enum amf_probe_id, struct event_* -- shared with amf_func_load.bpf.c */

/* ── attach_target arrays -- defined in ../amf_func_hooks.c, no header of
 * its own yet (this is the first consumer), so declared extern here the
 * same way ../amf_functions.h does for amf_functions.c's arrays. ── */
extern struct attach_target ngap_hook_funcs[];
extern struct attach_target nas_hook_funcs[];
extern struct attach_target sbi_hook_funcs[];
extern int ngap_hook_funcs_cnt;
extern int nas_hook_funcs_cnt;
extern int sbi_hook_funcs_cnt;

#define BPF_OBJ_PATH  "amf_func_load.bpf.o" /* built by this directory's Makefile from ../amf_func_load.bpf.c */
#define EVENTS_MAP    "events"              /* matches the BPF_MAP_TYPE_RINGBUF SEC(".maps") in amf_func_load.bpf.c */
#define POLL_INTERVAL_MS 200

/* ── Ctrl+C / SIGTERM -- same pattern as ../amf_loader.c and ../test_xdp.c ── */
static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { (void)sig; stop = 1; }

static void print_ts(FILE *f)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(f, "[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

#define LOG(...)   do { print_ts(stdout); printf(__VA_ARGS__); printf("\n"); } while (0)
#define ALERT(...) do { print_ts(stderr); fprintf(stderr, "*** ALERT: " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)

/* ── attach/detach, generic over struct bpf_object* (see file header) ─── */

/* Attaches every target in targets[0..cnt), against `bin_path` in process
 * `pid`. Unlike amf_comm.c's attach_programs(), does NOT bail on the first
 * failure -- logs it and keeps going, so one bad symbol name doesn't hide
 * whether the other 19 resolve. Returns the number successfully attached. */
static int attach_targets(struct bpf_object *obj, const char *bin_path, pid_t pid,
                           struct attach_target *targets, int cnt, const char *group_name)
{
    int ok = 0;

    for (int i = 0; i < cnt; i++) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .func_name = targets[i].func_name,
            .retprobe = targets[i].retprobe);

        struct bpf_program *prog = bpf_object__find_program_by_name(obj, targets[i].prog_name);
        if (!prog) {
            ALERT("%s: program \"%s\" not found in %s (BPF source/loader out of sync?)",
                  group_name, targets[i].prog_name, BPF_OBJ_PATH);
            continue;
        }

        targets[i].link = bpf_program__attach_uprobe_opts(prog, pid, bin_path, 0, &opts);
        if (!targets[i].link) {
            ALERT("%s: attach FAILED  %-24s -> %s%s (%s)",
                  group_name, targets[i].prog_name, targets[i].func_name,
                  targets[i].retprobe ? " [uretprobe]" : "", strerror(errno));
            continue;
        }

        LOG("attached  %-24s -> %s%s", targets[i].prog_name, targets[i].func_name,
            targets[i].retprobe ? " [uretprobe]" : "");
        ok++;
    }
    return ok;
}

static void detach_targets(struct attach_target *targets, int cnt)
{
    for (int i = 0; i < cnt; i++) {
        if (targets[i].link) {
            bpf_link__destroy(targets[i].link);
            targets[i].link = NULL;
        }
    }
}

/* ── event printing ──────────────────────────────────────────────────── */

/* Every struct event_* in ../amf_func_load_events.h starts with this exact
 * 16-byte prefix (ts_ns, pid, probe_id) in this exact order -- read it
 * first to decide how to interpret the rest, instead of guessing from
 * data_sz alone. */
struct evt_hdr {
    __u64 ts_ns;
    __u32 pid;
    __u32 probe_id;
};

static const char *sbi_probe_name(__u32 probe_id)
{
    switch (probe_id) {
    case PROBE_SBI_UE_CTX_XFER:   return "HTTPUEContextTransfer";
    case PROBE_SBI_N1N2_XFER:     return "HTTPN1N2MessageTransfer";
    case PROBE_SBI_SUB_CREATE:    return "HTTPCreateSubscription";
    case PROBE_SBI_POLICY_UPDATE: return "HTTPAmPolicyControlUpdateNotifyUpdate";
    case PROBE_SBI_POLICY_TERM:   return "HTTPAmPolicyControlUpdateNotifyTerminate";
    case PROBE_SBI_SM_STATUS:     return "HTTPSmContextStatusNotify";
    case PROBE_SBI_DEREG_NOTIFY:  return "HTTPHandleDeregistrationNotification";
    default:                      return "?";
    }
}

/* ngapType.NGAPPDU.Present -- NGAPPDU_PRESENT_* in amf_func_load.bpf.c
 * (not re-exported via the shared header, since it's parsing-internal, not
 * wire layout -- duplicated here as plain literals, the same way
 * ../test_xdp.c's own decoders carry their protocol knowledge locally). */
static const char *ngap_present_name(__s64 present)
{
    switch (present) {
    case 1:  return "InitiatingMessage";
    case 2:  return "SuccessfulOutcome";
    case 3:  return "UnsuccessfulOutcome";
    default: return "?";
    }
}

/* Compact one-line hex preview, "aa bb cc ... (+N more)" -- ground truth
 * for binary (ASN.1/NAS) payloads, not meant to be a full dump. */
static void print_hex_preview(const char *label, const __u8 *buf, __u32 len, __u32 max)
{
    if (len == 0) {
        printf("    %s: (empty)\n", label);
        return;
    }
    printf("    %s (%u bytes): ", label, len);
    __u32 n = len < max ? len : max;
    for (__u32 i = 0; i < n; i++)
        printf("%02x ", buf[i]);
    if (len > n)
        printf("... (+%u more)", len - n);
    printf("\n");
}

/* Printable-safe text preview -- SBI bodies are JSON, so this is normally
 * fully readable; non-printable bytes (or a truncated multi-byte capture)
 * become '.' rather than corrupting the terminal. */
static void print_text_preview(const char *label, const __u8 *buf, __u32 len, __u32 max)
{
    char tmp[256];
    __u32 n = len < max ? len : (max < sizeof(tmp) - 1 ? max : sizeof(tmp) - 1);
    for (__u32 i = 0; i < n; i++)
        tmp[i] = isprint(buf[i]) ? (char)buf[i] : '.';
    tmp[n] = '\0';
    printf("    %s (%u bytes)%s: %s\n", label, len, len > n ? ", truncated" : "", tmp);
}

static void print_ngap(const struct event_ngap *e)
{
    LOG("NGAP   pid=%u ran=0x%llx present=%s procedureCode=%lld",
        e->pid, (unsigned long long)e->ran_ptr, ngap_present_name(e->present),
        (long long)e->procedure_code);
    if (e->nas_pdu_len > 0)
        print_hex_preview("embedded NAS-PDU", e->nas_pdu, e->nas_pdu_len, 32);
}

static void print_nas(const struct event_nas *e)
{
    LOG("NAS    pid=%u ue=0x%llx procedureCode=%lld messageType=0x%02x accessType=\"%s\"",
        e->pid, (unsigned long long)e->ue_ptr, (long long)e->procedure_code,
        e->message_type, e->access_type);
}

static void print_sbi(const struct event_sbi *e)
{
    LOG("SBI    pid=%u %-40s %s %s", e->pid, sbi_probe_name(e->probe_id), e->method, e->path);
    if (e->param0_key[0])
        printf("    param0: %s=%s\n", e->param0_key, e->param0_val);
    if (e->param1_key[0])
        printf("    param1: %s=%s\n", e->param1_key, e->param1_val);
}

/* Prints a parsed-IE field only if sbi_parse_ies() actually found it --
 * see the "best-effort" caveat on struct event_sbi_body itself. */
#define PRINT_IE_STR(label, field) \
    do { if ((field)[0]) printf("    %-16s %s\n", label ":", (field)); } while (0)

static void print_sbi_body(const struct event_sbi_body *e)
{
    LOG("SBI-BODY pid=%u", e->pid);
    print_text_preview("body", e->body, e->body_len, 200);

    PRINT_IE_STR("reason", e->reason);
    PRINT_IE_STR("accessType", e->access_type);
    PRINT_IE_STR("cause", e->cause);
    PRINT_IE_STR("deregReason", e->dereg_reason);
    PRINT_IE_STR("nfId", e->nf_id);
}

static void print_sbi_authz(const struct event_sbi_authz *e)
{
    LOG("SBI-AUTHZ pid=%u value=\"%s\"", e->pid, e->value);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct evt_hdr))
        return 0; /* shouldn't happen -- every event_* struct has this prefix */

    const struct evt_hdr *hdr = data;

    switch (hdr->probe_id) {
    case PROBE_NGAP_DISPATCH:
        if (data_sz < sizeof(struct event_ngap)) return 0;
        print_ngap(data);
        break;
    case PROBE_NAS_DISPATCH:
        if (data_sz < sizeof(struct event_nas)) return 0;
        print_nas(data);
        break;
    case PROBE_SBI_UE_CTX_XFER:
    case PROBE_SBI_N1N2_XFER:
    case PROBE_SBI_SUB_CREATE:
    case PROBE_SBI_POLICY_UPDATE:
    case PROBE_SBI_POLICY_TERM:
    case PROBE_SBI_SM_STATUS:
    case PROBE_SBI_DEREG_NOTIFY:
        if (data_sz < sizeof(struct event_sbi)) return 0;
        print_sbi(data);
        break;
    case PROBE_SBI_RAW_BODY:
        if (data_sz < sizeof(struct event_sbi_body)) return 0;
        print_sbi_body(data);
        break;
    case PROBE_SBI_AUTHZ_HDR:
        if (data_sz < sizeof(struct event_sbi_authz)) return 0;
        print_sbi_authz(data);
        break;
    default:
        LOG("unknown probe_id=%u (%zu bytes) -- amf_func_load.bpf.c / amf_func_load_events.h out of sync?",
            hdr->probe_id, data_sz);
        break;
    }
    return 0;
}

/* Blocks (polling once a second) until an "amf" process exists, same
 * "attach automatically, don't require the target already running"
 * behavior as ../test_xdp.c's wait_for_ifindex(). Returns its pid, or -1
 * if a signal set `stop` while waiting. */
static pid_t wait_for_amf_pid(void)
{
    bool printed = false;
    while (!stop) {
        int pid = find_nf("amf");
        if (pid > 0)
            return (pid_t)pid;
        if (!printed) {
            LOG("waiting for an \"amf\" process to appear...");
            printed = true;
        }
        sleep(1);
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr,
                "%s: must run as root -- attaching uprobes needs CAP_BPF "
                "(read access to the target's memory via /proc/<pid>/exe).\n"
                "Try: sudo ./%s\n",
                argc > 0 ? argv[0] : "test_func_load", argc > 0 ? argv[0] : "test_func_load");
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    LOG("test_func_load: loading %s", BPF_OBJ_PATH);

    pid_t pid = wait_for_amf_pid();
    if (pid < 0)
        return 0; /* Ctrl+C while still waiting -- nothing was attached, nothing to clean up */

    char bin_path[64];
    snprintf(bin_path, sizeof(bin_path), "/proc/%d/exe", pid);
    LOG("found amf: pid=%d exe=%s", pid, bin_path);

    struct bpf_object *obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "test_func_load: bpf_object__open_file(%s): %s\n", BPF_OBJ_PATH, strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "test_func_load: bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, EVENTS_MAP);
    if (!events_map) {
        fprintf(stderr, "test_func_load: map \"%s\" not found in %s\n", EVENTS_MAP, BPF_OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "test_func_load: ring_buffer__new: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* Attach every group -- see attach_targets()'s header comment for why
     * this deliberately doesn't abort on the first failure. */
    LOG("attaching uprobes to pid=%d ...", pid);
    int ok = 0, total = ngap_hook_funcs_cnt + nas_hook_funcs_cnt + sbi_hook_funcs_cnt;
    ok += attach_targets(obj, bin_path, pid, ngap_hook_funcs, ngap_hook_funcs_cnt, "ngap");
    ok += attach_targets(obj, bin_path, pid, nas_hook_funcs,  nas_hook_funcs_cnt,  "nas");
    ok += attach_targets(obj, bin_path, pid, sbi_hook_funcs,  sbi_hook_funcs_cnt,  "sbi");

    LOG("attach summary: %d/%d targets attached", ok, total);
    if (ok == 0) {
        fprintf(stderr, "test_func_load: nothing attached -- see ALERT lines above\n");
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 1;
    }

    LOG("watching \"%s\" ringbuf (Ctrl+C to stop)...", EVENTS_MAP);
    while (!stop) {
        int n = ring_buffer__poll(rb, POLL_INTERVAL_MS);
        if (stop)
            break;
        if (n < 0 && n != -EINTR)
            ALERT("ring_buffer__poll: %d", n);

        /* Uprobes don't get a detach notification the way XDP programs do
         * (see ../test_xdp.c's watchdog) -- the only thing that can make
         * them go silent is the traced process itself exiting, which just
         * means events stop arriving. Surface that explicitly instead of
         * quietly going idle forever. */
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            ALERT("pid=%d (amf) is no longer running -- its uprobes are now dead; exiting", pid);
            break;
        }
    }

    LOG("shutting down (Ctrl+C) -- detaching %d probe(s)", ok);
    detach_targets(ngap_hook_funcs, ngap_hook_funcs_cnt);
    detach_targets(nas_hook_funcs,  nas_hook_funcs_cnt);
    detach_targets(sbi_hook_funcs,  sbi_hook_funcs_cnt);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
