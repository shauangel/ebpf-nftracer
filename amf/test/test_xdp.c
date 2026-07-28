/*
 * test_xdp.c — auto-attaching loader + detach watchdog for ../xdp_ngap.c.
 *
 * ../xdp_ngap.c is the passive, legacy XDP program (single SEC("xdp")
 * program "xdp_prog", no maps of its own -- see ../README.md's
 * "xdp_ngap.c (legacy, superseded)" section): it parses Ethernet/IP/SCTP/
 * NGAP and bpf_printk()s the procedure code, always returning XDP_PASS.
 * ../README.md documents attaching it by hand:
 *
 *   clang -O2 -g -target bpf ... -c amf_xdp.c -o amf_xdp.o
 *   sudo ip link set dev veth5538fab xdp obj amf_xdp.o sec xdp
 *
 * This file does that same load+attach from C instead of a shell one-liner,
 * against the exact same target interface, and then keeps running as a
 * watchdog:
 *
 *   1. attaches automatically -- waits for veth5538fab to exist rather
 *      than requiring it to already be up, and picks native (driver) XDP
 *      mode first, falling back to generic (SKB) mode if the interface
 *      doesn't support native XDP.
 *   2. alerts if the program is ever no longer the one attached to that
 *      interface -- whether because someone ran `ip link set dev
 *      veth5538fab xdp off`, a different program replaced it, or the
 *      interface itself was torn down and possibly recreated. Detected by
 *      polling bpf_xdp_query_id() every POLL_INTERVAL_SEC seconds and
 *      comparing against the id this process itself attached -- there is
 *      no netlink "XDP program removed" event to subscribe to instead, so
 *      polling is the standard way real XDP loaders (e.g. xdp-loader)
 *      handle this too.
 *
 * Requires Linux, libbpf with bpf_xdp_attach()/bpf_xdp_detach()/
 * bpf_xdp_query_id() (libbpf >= 0.6), and root (CAP_BPF + CAP_NET_ADMIN --
 * attaching an XDP program needs real network privileges on top of the
 * CAP_BPF the rest of this test suite already requires).
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>          /* if_nametoindex() */
#include <linux/if_link.h>   /* XDP_FLAGS_* attach-mode flags */

#include <bpf/libbpf.h>      /* bpf_object__open_file/__load, bpf_program__fd */
#include <bpf/bpf.h>         /* bpf_xdp_attach/detach/query_id, bpf_obj_get_info_by_fd */

/* Default attach target -- the host-side veth of the AMF container's N2
 * interface, same as ../amf_xdp.c's documented attach point. Overridable
 * as argv[1] for testing against some other interface without editing
 * this file. */
#define DEFAULT_IFACE "veth5538fab"

/* Built by this directory's Makefile (see the xdp_ngap.bpf.o rule) from
 * ../xdp_ngap.c -- kept in amf/test/, nothing added to amf/ itself. */
#define XDP_OBJ_PATH  "xdp_ngap.bpf.o"
#define XDP_PROG_NAME "xdp_prog" /* matches SEC("xdp") int xdp_prog(...) in xdp_ngap.c */

#define POLL_INTERVAL_SEC 2

/* ── Ctrl+C / SIGTERM handling -- same pattern ../amf_loader.c uses ────── */
static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { (void)sig; stop = 1; }

/* Wall-clock "HH:MM:SS" prefix for log lines (distinct from
 * ../amf_loader.c's fmt_ts(), which formats a boot-relative
 * bpf_ktime_get_ns() timestamp -- there's no BPF ring-buffer event here,
 * just this process's own clock). */
static void print_ts(FILE *f)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(f, "[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

#define ALERT(...) \
    do { \
        print_ts(stderr); \
        fprintf(stderr, "*** ALERT: " __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } while (0)

#define LOG(...) \
    do { \
        print_ts(stdout); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } while (0)

/* Blocks (polling once a second) until `ifname` exists, returning its
 * ifindex -- or -1 if a signal set `stop` while waiting. This is what
 * makes attaching "automatic": the caller doesn't need the interface to
 * already be up (e.g. the AMF container hasn't started yet), just
 * eventually present. */
static int wait_for_ifindex(const char *ifname)
{
    bool printed = false;
    while (!stop) {
        unsigned idx = if_nametoindex(ifname);
        if (idx != 0)
            return (int)idx;
        if (!printed) {
            LOG("waiting for interface \"%s\" to appear...", ifname);
            printed = true;
        }
        sleep(1);
    }
    return -1;
}

/* Attaches prog_fd to ifindex, trying native (driver) XDP mode first and
 * falling back to generic (SKB) mode -- native mode isn't supported on
 * every interface/driver, but generic mode works everywhere, including a
 * veth pair, at some per-packet cost. XDP_FLAGS_UPDATE_IF_NOEXIST makes
 * both attempts fail (instead of silently replacing) if some OTHER
 * program is already attached, so this loader can never accidentally
 * steal a program a real session already has running on the interface.
 * On success, *flags_used records which mode won, needed later to detach
 * with matching flags. Returns 0 on success, -1 (errno set from the last
 * attempt) if neither mode worked. */
static int attach_xdp(int ifindex, int prog_fd, __u32 *flags_used)
{
    static const __u32 modes[] = {
        XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
    };
    static const char *mode_names[] = { "native/driver", "generic/SKB" };

    int err = 0;
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        err = bpf_xdp_attach(ifindex, prog_fd, modes[i], NULL);
        if (err == 0) {
            *flags_used = modes[i];
            LOG("attached xdp_prog to ifindex %d in %s mode", ifindex, mode_names[i]);
            return 0;
        }
    }
    if (err == -EBUSY || errno == EBUSY)
        fprintf(stderr,
                "attach_xdp: ifindex %d already has an XDP program attached "
                "(EBUSY) -- run `sudo ip link set dev <iface> xdp off` first "
                "if that's a stale program from a previous, uncleanly-stopped "
                "run of this loader.\n", ifindex);
    return -1;
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr,
                "%s: must run as root -- attaching an XDP program needs "
                "CAP_BPF + CAP_NET_ADMIN.\nTry: sudo ./%s\n",
                argc > 0 ? argv[0] : "test_xdp", argc > 0 ? argv[0] : "test_xdp");
        return 1;
    }

    const char *ifname = (argc > 1) ? argv[1] : DEFAULT_IFACE;

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    LOG("test_xdp: loading %s (prog \"%s\") for interface \"%s\"",
        XDP_OBJ_PATH, XDP_PROG_NAME, ifname);

    /* Requirement 1: attach automatically -- don't require the interface
     * to already exist at startup. */
    int ifindex = wait_for_ifindex(ifname);
    if (ifindex < 0)
        return 0; /* Ctrl+C while still waiting -- nothing was attached, nothing to clean up */

    struct bpf_object *obj = bpf_object__open_file(XDP_OBJ_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "test_xdp: bpf_object__open_file(%s): %s\n",
                XDP_OBJ_PATH, strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "test_xdp: bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, XDP_PROG_NAME);
    if (!prog) {
        fprintf(stderr, "test_xdp: program \"%s\" not found in %s\n",
                XDP_PROG_NAME, XDP_OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    __u32 xdp_flags = 0;
    if (attach_xdp(ifindex, prog_fd, &xdp_flags) != 0) {
        fprintf(stderr, "test_xdp: attach_xdp: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* Record OUR program's kernel id -- what the watchdog loop below
     * compares against every poll to notice a detach/replace. */
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
        fprintf(stderr, "test_xdp: bpf_obj_get_info_by_fd: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, xdp_flags, NULL);
        bpf_object__close(obj);
        return 1;
    }
    __u32 our_prog_id = info.id;
    LOG("attached: ifindex=%d prog_id=%u -- watching for detachment (Ctrl+C to stop)",
        ifindex, our_prog_id);

    /* Requirement 2: alert on detachment, in any of its forms. Tracked as
     * a small state machine so an alert only prints once per state
     * CHANGE (not once per poll) and a "recovered" line prints when
     * things go back to normal -- avoids a flood of identical alerts
     * every POLL_INTERVAL_SEC while the underlying problem persists. */
    enum { STATE_ATTACHED, STATE_DETACHED, STATE_REPLACED, STATE_IFACE_GONE } state = STATE_ATTACHED;

    while (!stop) {
        sleep(POLL_INTERVAL_SEC);
        if (stop)
            break;

        unsigned cur_ifindex = if_nametoindex(ifname);
        if (cur_ifindex == 0) {
            /* Case: the interface itself vanished (container/veth torn
             * down) -- the XDP program went with it. */
            if (state != STATE_IFACE_GONE) {
                ALERT("interface \"%s\" disappeared -- xdp_prog is no longer attached anywhere", ifname);
                state = STATE_IFACE_GONE;
            }
            int new_idx = wait_for_ifindex(ifname); /* blocks until it comes back, or Ctrl+C */
            if (stop)
                break;
            ifindex = new_idx;
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("interface \"%s\" reappeared (ifindex=%d) -- re-attached automatically", ifname, ifindex);
                state = STATE_ATTACHED;
            } else {
                ALERT("interface \"%s\" reappeared but re-attach FAILED: %s", ifname, strerror(errno));
            }
            continue;
        }

        if ((int)cur_ifindex != ifindex) {
            /* Same name, different ifindex -- the old interface was
             * deleted and a new one created between polls without us
             * ever observing cur_ifindex==0 in between. Still means our
             * attachment (which was keyed to the OLD ifindex) is gone. */
            ALERT("interface \"%s\" was recreated (ifindex %d -> %d) -- re-attaching", ifname, ifindex, (int)cur_ifindex);
            ifindex = (int)cur_ifindex;
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("re-attached to new ifindex %d", ifindex);
                state = STATE_ATTACHED;
            } else {
                ALERT("re-attach after interface recreation FAILED: %s", strerror(errno));
                state = STATE_DETACHED;
            }
            continue;
        }

        __u32 cur_prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &cur_prog_id) != 0) {
            ALERT("failed to query XDP status on \"%s\": %s", ifname, strerror(errno));
            continue;
        }

        if (cur_prog_id == 0) {
            /* Case: someone ran `ip link set dev <iface> xdp off`, or
             * equivalent -- no XDP program attached at all anymore. */
            if (state != STATE_DETACHED) {
                ALERT("xdp_prog was DETACHED from \"%s\" (no XDP program attached)", ifname);
                state = STATE_DETACHED;
            }
            if (attach_xdp(ifindex, prog_fd, &xdp_flags) == 0) {
                LOG("re-attached automatically after detach");
                state = STATE_ATTACHED;
            }
        } else if (cur_prog_id != our_prog_id) {
            /* Case: a DIFFERENT XDP program is now attached -- e.g.
             * someone loaded amf_xdp.o (or anything else) over top of
             * ours. Deliberately does NOT fight to reclaim the interface
             * -- silently overriding another program back would be just
             * as surprising as the replacement itself. */
            if (state != STATE_REPLACED) {
                ALERT("xdp_prog on \"%s\" was REPLACED (expected prog_id=%u, found prog_id=%u)",
                      ifname, our_prog_id, cur_prog_id);
                state = STATE_REPLACED;
            }
        } else if (state != STATE_ATTACHED) {
            /* Recovered on its own (e.g. someone re-ran the exact same
             * ip link command pointing back at our program id). */
            LOG("xdp_prog is attached to \"%s\" again (prog_id=%u)", ifname, our_prog_id);
            state = STATE_ATTACHED;
        }
        /* state == STATE_ATTACHED and nothing changed: stay silent, per
         * this suite's convention of only printing on state changes. */
    }

    LOG("shutting down (Ctrl+C) -- detaching xdp_prog from \"%s\"", ifname);
    if (state == STATE_ATTACHED || state == STATE_REPLACED) {
        /* Only detach if we still believe OUR program (or at least
         * something) is at this ifindex; if the interface is gone there's
         * nothing left to detach. STATE_REPLACED: attempt it anyway --
         * bpf_xdp_detach() with our flags is a no-op / harmless error if
         * we don't actually own what's attached now. */
        if (bpf_xdp_detach(ifindex, xdp_flags, NULL) != 0)
            fprintf(stderr, "test_xdp: bpf_xdp_detach: %s (may already be detached)\n", strerror(errno));
    }
    bpf_object__close(obj);
    return 0;
}
