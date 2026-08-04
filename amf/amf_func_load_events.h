#ifndef AMF_FUNC_LOAD_EVENTS_H
#define AMF_FUNC_LOAD_EVENTS_H

/*
 * amf_func_load_events.h — event schema for amf_func_load.bpf.c's "events"
 * ringbuf. #include'd on both sides, same pattern as xdp_ngap_event.h /
 * test_xdp.c:
 *   - by amf_func_load.bpf.c (BPF/CO-RE) to fill records
 *   - by test/test_func_load.c (userspace, via libbpf's ring_buffer__new())
 *     to interpret the same bytes read back off that ringbuf
 *
 * No typedefs of its own -- relies on __u8/__u16/__u32/__u64 already being
 * visible from whichever side #include's this: "vmlinux.h" on the BPF side,
 * <bpf/libbpf.h>/<bpf/bpf.h> (which pull in linux/types.h) on the userspace
 * side. Field-level rationale lives in amf_func_load.bpf.c next to where
 * each field is populated -- kept out of here to avoid the two drifting out
 * of sync with each other.
 */

enum amf_probe_id {
	PROBE_NGAP_DISPATCH = 1, /* ngap.dispatchMain            -> amf_ngap_disp   */
	PROBE_NAS_DISPATCH,      /* nas.Dispatch                 -> amf_nas_disp    */
	PROBE_SBI_UE_CTX_XFER,   /* HTTPUEContextTransfer         -> amf_sbi_ue_xfer */
	PROBE_SBI_N1N2_XFER,     /* HTTPN1N2MessageTransfer       -> amf_sbi_n1n2    */
	PROBE_SBI_SUB_CREATE,    /* HTTPCreateSubscription        -> amf_sbi_sub_crt */
	PROBE_SBI_POLICY_UPDATE, /* HTTPAmPolicyControlUpdateNotifyUpdate -> amf_sbi_pol_upd */
	PROBE_SBI_POLICY_TERM,   /* HTTPAmPolicyControlUpdateNotifyTerminate -> amf_sbi_pol_trm */
	PROBE_SBI_SM_STATUS,     /* HTTPSmContextStatusNotify     -> amf_sbi_sm_ntfy */
	PROBE_SBI_DEREG_NOTIFY,  /* HTTPHandleDeregistrationNotification -> amf_sbi_dereg */
	PROBE_SBI_RAW_BODY,      /* gin.(*Context).GetRawData [uretprobe] -> amf_sbi_body */
	PROBE_SBI_AUTHZ_HDR,     /* net/http.Header.Get("Authorization") [uretprobe] -> amf_http_hdr_get_ret */
};

/* ── NGAP: ngap.dispatchMain ─────────────────────────────────────────── */

#define NAS_PDU_MAX     512
#define ACCESS_TYPE_MAX 24

struct event_ngap {
	__u64 ts_ns;
	__u32 pid;
	__u32 probe_id;
	__u64 ran_ptr;
	__s64 present;
	__s64 procedure_code;
	__u32 nas_pdu_len;
	__u8  nas_pdu[NAS_PDU_MAX];
};

/* ── NAS: nas.Dispatch ───────────────────────────────────────────────── */

struct event_nas {
	__u64 ts_ns;
	__u32 pid;
	__u32 probe_id;
	__u64 ue_ptr;
	__s64 procedure_code;
	__u8  message_type;
	char  access_type[ACCESS_TYPE_MAX];
};

/* ── SBI: the 7 HTTPXxx entry probes ─────────────────────────────────── */

#define METHOD_MAX 8
#define PATH_MAX   128
#define PKEY_MAX   32
#define PVAL_MAX   64

struct event_sbi {
	__u64 ts_ns;
	__u32 pid;
	__u32 probe_id;
	__u64 ctx_ptr;
	char  method[METHOD_MAX];
	char  path[PATH_MAX];
	char  param0_key[PKEY_MAX];
	char  param0_val[PVAL_MAX];
	char  param1_key[PKEY_MAX];
	char  param1_val[PVAL_MAX];
};

/* ── SBI: raw body + best-effort parsed IEs ──────────────────────────── */

#define SBI_BODY_MAX 1024
#define IE_STR_MAX   32

struct event_sbi_body {
	__u64 ts_ns;
	__u32 pid;
	__u32 probe_id;
	__u32 body_len;
	__u8  body[SBI_BODY_MAX];

	/* best-effort parsed IEs -- see sbi_ie_keys[]/sbi_parse_ies() in
	 * amf_func_load.bpf.c; zero-length string means the key was not
	 * found. Deliberately just these 5 -- see the comment above
	 * IE_SCAN_MAX there for what each maps to and why. */
	char  reason[IE_STR_MAX];
	char  access_type[IE_STR_MAX];
	char  cause[IE_STR_MAX];
	char  dereg_reason[IE_STR_MAX];
	char  nf_id[IE_STR_MAX];
};

/* ── SBI: Authorization header capture ───────────────────────────────── */

#define AUTHZ_VAL_MAX 512

struct event_sbi_authz {
	__u64 ts_ns;
	__u32 pid;
	__u32 probe_id;
	__u32 value_len;
	char  value[AUTHZ_VAL_MAX]; /* raw header value, e.g. "Bearer <jwt>" */
};

#endif /* AMF_FUNC_LOAD_EVENTS_H */
