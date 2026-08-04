// SPDX-License-Identifier: GPL-2.0
/*
 * amf_func_load.bpf.c — uprobe programs for every hook point declared in
 * amf_func_hooks.c (ngap_hook_funcs[], nas_hook_funcs[], sbi_hook_funcs[]).
 *
 * Reading Go arguments from a uprobe:
 * Go >=1.17 uses a register-based calling convention (ABIInternal), NOT the
 * platform C ABI, so PT_REGS_PARM1..N from bpf_tracing.h (which assume the
 * SysV C order) are the WRONG registers for Go args. Multi-word Go values
 * (string = {ptr,len}, slice = {ptr,len,cap}, interface = {type,data}) are
 * decomposed and each word consumes one integer register in sequence. Per
 * cmd/compile/abi-internal.md the amd64 integer-register sequence is:
 *   RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11
 * GO_ARGn() below implements that sequence for x86_64 only, matching the
 * `struct pt_regs` actually vendored in analysis/vmlinux.h:33892-33922 (kernel
 * 6.x — the fred_cs/fred_ss union members at the tail are x86 FRED, present
 * since ~6.9). That vmlinux.h has no arm64 pt_regs in it (bpftool generates
 * one arch per dump), so an arm64 build needs its own vmlinux.h dumped on an
 * arm64 host before GO_ARGn can be extended with a `regs[]`-indexed variant
 * — deliberately left out here rather than shipped unverified. The receiver
 * of a pointer-receiver method (e.g. (s *Server) HTTPXxx) is argument 1,
 * exactly like a leading plain parameter.
 *
 * vmlinux.h wraps every struct/union it emits in
 * __attribute__((preserve_access_index)) (see its own line 4-5 pragma), so
 * every ctx->ax / ctx->bx / ... access below is a CO-RE relocation: libbpf
 * patches the actual field offset in from the running kernel's BTF at load
 * time. That makes the pt_regs reads portable across kernel builds even
 * though ax/bx/../r11 aren't the first fields declared in the struct.
 * CO-RE does NOT help below this point, though — the Go/gin struct offsets
 * have no BTF, are not covered by vmlinux.h, and stay hardcoded.
 *
 * Struct offsets below are hand-derived from the exact dependency versions
 * pinned in this repo's go.sum, for linux/amd64 (8-byte words, 8-byte
 * pointer/int/slice-word alignment, no field reordering — the Go compiler
 * preserves declaration order and only inserts alignment padding):
 *   github.com/free5gc/ngap    v1.1.3   (ngapType.*)
 *   github.com/free5gc/nas     v1.2.3   (nas.Message, nas.GmmMessage)
 *   github.com/free5gc/aper    v1.1.1   (aper.OctetString = []byte, aper.Enumerated = uint64)
 *   github.com/gin-gonic/gin   v1.10.0  (gin.Context, gin.Param)
 *   net/http, net/url          go1.26.2 stdlib
 * A dependency bump that reorders/adds struct fields silently breaks these
 * offsets — there is no compiler to catch it, only wrong bytes in the
 * ringbuf. Production-grade Go-uprobe tooling (Pixie, Beyla, Parca) computes
 * these from the *target binary's* DWARF at attach time instead of trusting
 * hardcoded constants; the OFF_* macros below are grouped and named so a
 * loader can override them (e.g. patch this file's generated header, or make
 * them BPF .rodata globals set from userspace) without touching probe logic.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "amf_func_load_events.h" /* enum amf_probe_id + every struct event_* below -- shared with test/test_func_load.c */

char LICENSE[] SEC("license") = "GPL";

/* ---------------------------------------------------------------------- */
/* Go ABIInternal integer-register argument order (x86_64, kernel 6.x —   */
/* field names verified against analysis/vmlinux.h:33892-33922)           */
/* ---------------------------------------------------------------------- */

#define GO_ARG1(ctx) ((ctx)->ax)
#define GO_ARG2(ctx) ((ctx)->bx)
#define GO_ARG3(ctx) ((ctx)->cx)
#define GO_ARG4(ctx) ((ctx)->di)
#define GO_ARG5(ctx) ((ctx)->si)

/* Results are assigned the SAME integer-register sequence, restarting at RAX
 * independent of how many argument words preceded them -- so at a uretprobe
 * (function return) the first up-to-5 result words land in this same
 * ax/bx/cx/di/si set. Aliased separately purely for readability at call sites. */
#define GO_RET1(ctx) ((ctx)->ax)
#define GO_RET2(ctx) ((ctx)->bx)
#define GO_RET3(ctx) ((ctx)->cx)
#define GO_RET4(ctx) ((ctx)->di)
#define GO_RET5(ctx) ((ctx)->si)

/* ---------------------------------------------------------------------- */
/* Ring buffer: every probe below emits into this one buffer              */
/* ---------------------------------------------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

/*
 * Every event_* probe below reserves its own struct off `events` and needs
 * it zeroed first (bpf_ringbuf_reserve() does NOT zero the memory it hands
 * back -- it can be leftover bytes from a previous event) -- but plain
 * `__builtin_memset(e, 0, sizeof(*e))` only works for small, compile-time
 * sizes on the BPF target: past clang's inlining threshold it tries to
 * lower to a real memset() *libcall*, which BPF has no libc to resolve
 * ("call to built-in function 'memset' is not supported"). Every event_*
 * struct here (amf_func_load_events.h) is well past that threshold -- the
 * smallest is ~560 bytes (event_ngap's nas_pdu[512]), the largest ~1.3KB
 * (event_sbi_body's body[1024] plus the parsed-IE fields).
 *
 * Fixed with the standard eBPF workaround: a #pragma-unrolled loop of
 * 8-byte word stores, with the unroll count computed from sizeof(*(e)) AT
 * THE MACRO'S EXPANSION SITE, so each call site gets an unroll bound
 * that's an exact compile-time constant for ITS OWN struct -- no shared
 * "size to the largest struct, break early for smaller ones" logic that
 * would depend on the optimizer proving the extra iterations dead. The
 * sizeof(*(e))%8==0 assumption always holds here: every event_* struct
 * starts with a __u64, so C's own struct-layout rules pad the *total* size
 * up to a multiple of the struct's 8-byte alignment requirement regardless
 * of what's declared after it.
 *
 * The store pointer is `volatile` -- NOT for memory-visibility semantics
 * (this is single-threaded per-invocation scratch memory), but because
 * without it LLVM's LoopIdiomRecognize pass (-O2) pattern-matches "a loop
 * that stores zero across a contiguous range" and rewrites it right back
 * into a memset()/llvm.memset call of its own accord, walking straight
 * back into the exact same "not supported" error this was written to
 * avoid -- #pragma unroll alone doesn't stop it, since idiom recognition
 * can fire on the loop before unrolling ever happens. A volatile store
 * can't be coalesced into a library call, which defeats the pattern match.
 */
#define ZERO_EVENT(e) \
	do { \
		_Static_assert(sizeof(*(e)) % 8 == 0, "event struct size must be a multiple of 8"); \
		volatile __u64 *_zp = (volatile __u64 *)(e); \
		_Pragma("unroll") \
		for (__u32 _zi = 0; _zi < sizeof(*(e)) / 8; _zi++) \
			_zp[_zi] = 0; \
	} while (0)

/* ======================================================================== */
/* NGAP: ngap.dispatchMain(ran *context.AmfRan, message *ngapType.NGAPPDU)  */
/* ======================================================================== */

/*
 * ngapType.NGAPPDU (ngap@v1.1.3/ngapType/NGAPPDU.go:13):
 *   Present int; InitiatingMessage *T; SuccessfulOutcome *T; UnsuccessfulOutcome *T
 * ngapType.InitiatingMessage (InitiatingMessage.go:5):
 *   ProcedureCode ProcedureCode{Value int64}; Criticality; Value InitiatingMessageValue
 * -> ProcedureCode.Value sits at offset 0 of *InitiatingMessage (SuccessfulOutcome /
 *    UnsuccessfulOutcome have the identical ProcedureCode-first layout).
 *
 * For the two procedures that carry the initial/uplink NAS-PDU (the IE this
 * whole registration analysis cares about), we additionally walk the
 * ASN.1 protocol-IE list to pull out the raw NAS-PDU octet string:
 *   InitiatingMessageValue.InitialUEMessage    is field index 29 -> offset 232
 *   InitiatingMessageValue.UplinkNASTransport  is field index 49 -> offset 392
 *   (both counted from InitiatingMessageValue's declared field order, each
 *   field after `Present int` is a uniform 8-byte pointer)
 * InitialUEMessage{ ProtocolIEs ProtocolIEContainerInitialUEMessageIEs{ List []InitialUEMessageIEs } }
 * UplinkNASTransport{ ProtocolIEs ProtocolIEContainerUplinkNASTransportIEs{ List []UplinkNASTransportIEs } }
 * -> ProtocolIEs is embedded at offset 0, so the slice header {ptr,len,cap} of
 *    List is at offset 0/8/16 of the message struct itself.
 * InitialUEMessageIEs{ Id ProtocolIEID{int64}; Criticality{Enumerated=uint64}; Value InitialUEMessageIEsValue }
 *   -> elem+0  Id.Value (int64)
 *   -> elem+16 Value.Present (int)
 *   -> elem+32 Value.NASPDU (*NASPDU), when Id.Value == ProtocolIEIDNASPDU (38)
 *   sizeof(InitialUEMessageIEs) = 96
 * UplinkNASTransportIEs{ Id; Criticality; Value UplinkNASTransportIEsValue }
 *   -> elem+0  Id.Value
 *   -> elem+16 Value.Present
 *   -> elem+40 Value.NASPDU, when Id.Value == 38
 *   sizeof(UplinkNASTransportIEs) = 56
 * NASPDU{ Value aper.OctetString }, OctetString = []byte -> slice header at offset 0.
 */

#define OFF_NGAPPDU_PRESENT            0
#define OFF_NGAPPDU_INITIATING         8
#define OFF_NGAPPDU_SUCCESSFUL         16
#define OFF_NGAPPDU_UNSUCCESSFUL       24
#define NGAPPDU_PRESENT_INITIATING     1
#define NGAPPDU_PRESENT_SUCCESSFUL     2
#define NGAPPDU_PRESENT_UNSUCCESSFUL   3

#define OFF_MSG_PROCEDURE_CODE         0  /* Initiating/Successful/UnsuccessfulMessage.ProcedureCode.Value */
#define OFF_MSGVALUE_FIELD             16 /* Initiating/Successful/UnsuccessfulMessage.Value (open-type struct) */

#define OFF_INITMSGVAL_INITIAL_UE_MSG  232 /* InitiatingMessageValue.InitialUEMessage   */
#define OFF_INITMSGVAL_UPLINK_NAS      392 /* InitiatingMessageValue.UplinkNASTransport */
#define PROC_CODE_INITIAL_UE_MESSAGE   15  /* ngapType.ProcedureCodeInitialUEMessage    */
#define PROC_CODE_UPLINK_NAS_TRANSPORT 46  /* ngapType.ProcedureCodeUplinkNASTransport  */

#define OFF_IE_LIST_HDR                0   /* ProtocolIEContainer{List []T} embedded at offset 0 */
#define SZ_INIT_UE_MSG_IE              96
#define OFF_INIT_UE_MSG_IE_ID          0
#define OFF_INIT_UE_MSG_IE_PRESENT     16
#define OFF_INIT_UE_MSG_IE_NASPDU      32
#define SZ_UPLINK_NAS_IE               56
#define OFF_UPLINK_NAS_IE_ID           0
#define OFF_UPLINK_NAS_IE_PRESENT      16
#define OFF_UPLINK_NAS_IE_NASPDU       40
#define PROTOCOL_IE_ID_NAS_PDU         38

#define MAX_IE_SCAN   12   /* generous for a real InitialUEMessage (~6-9 IEs) */
/* NAS_PDU_MAX / struct event_ngap: amf_func_load_events.h */

/* Reads message->{Initiating,Successful,Unsuccessful}Message.ProcedureCode.Value
 * into *out_proc, and returns the pointer to that sub-message struct (or 0). */
static __always_inline __u64 ngap_submsg_ptr(void *message, __s64 present, __s64 *out_proc)
{
	__u64 sub_ptr = 0;
	int off;

	if (present == NGAPPDU_PRESENT_INITIATING)
		off = OFF_NGAPPDU_INITIATING;
	else if (present == NGAPPDU_PRESENT_SUCCESSFUL)
		off = OFF_NGAPPDU_SUCCESSFUL;
	else if (present == NGAPPDU_PRESENT_UNSUCCESSFUL)
		off = OFF_NGAPPDU_UNSUCCESSFUL;
	else
		return 0;

	if (bpf_probe_read_user(&sub_ptr, sizeof(sub_ptr), (void *)((__u64)message + off)))
		return 0;
	if (!sub_ptr)
		return 0;
	bpf_probe_read_user(out_proc, sizeof(*out_proc), (void *)(sub_ptr + OFF_MSG_PROCEDURE_CODE));
	return sub_ptr;
}

/* Only meaningful for InitiatingMessage (InitialUEMessage / UplinkNASTransport
 * are both request-direction procedures). Scans the IE list for the NAS-PDU
 * open-type IE and copies its raw octet string into the reserved event. */
static __always_inline void ngap_copy_embedded_nas_pdu(struct event_ngap *e, __u64 sub_ptr, __s64 proc_code)
{
	__u64 value_ptr = sub_ptr + OFF_MSGVALUE_FIELD; /* InitiatingMessageValue is embedded, not a pointer */
	__u64 msg_ptr = 0;
	__u64 list_ptr = 0;
	__s64 list_len = 0;
	int ie_size, id_off, present_off, naspdu_off;

	if (proc_code == PROC_CODE_INITIAL_UE_MESSAGE) {
		bpf_probe_read_user(&msg_ptr, sizeof(msg_ptr), (void *)(value_ptr + OFF_INITMSGVAL_INITIAL_UE_MSG));
		ie_size = SZ_INIT_UE_MSG_IE;
		id_off = OFF_INIT_UE_MSG_IE_ID;
		present_off = OFF_INIT_UE_MSG_IE_PRESENT;
		naspdu_off = OFF_INIT_UE_MSG_IE_NASPDU;
	} else if (proc_code == PROC_CODE_UPLINK_NAS_TRANSPORT) {
		bpf_probe_read_user(&msg_ptr, sizeof(msg_ptr), (void *)(value_ptr + OFF_INITMSGVAL_UPLINK_NAS));
		ie_size = SZ_UPLINK_NAS_IE;
		id_off = OFF_UPLINK_NAS_IE_ID;
		present_off = OFF_UPLINK_NAS_IE_PRESENT;
		naspdu_off = OFF_UPLINK_NAS_IE_NASPDU;
	} else {
		return;
	}
	if (!msg_ptr)
		return;

	bpf_probe_read_user(&list_ptr, sizeof(list_ptr), (void *)(msg_ptr + OFF_IE_LIST_HDR + 0));
	bpf_probe_read_user(&list_len, sizeof(list_len), (void *)(msg_ptr + OFF_IE_LIST_HDR + 8));
	if (!list_ptr || list_len <= 0)
		return;

#pragma unroll
	for (int i = 0; i < MAX_IE_SCAN; i++) {
		if (i >= list_len)
			break;

		__u64 elem = list_ptr + (i * ie_size);
		__s64 id_val = 0;

		bpf_probe_read_user(&id_val, sizeof(id_val), (void *)(elem + id_off));
		if (id_val != PROTOCOL_IE_ID_NAS_PDU)
			continue;

		__u64 naspdu_ptr = 0;

		bpf_probe_read_user(&naspdu_ptr, sizeof(naspdu_ptr), (void *)(elem + naspdu_off));
		if (!naspdu_ptr)
			break;

		__u64 oct_ptr = 0;
		__s64 oct_len = 0;

		/* NASPDU{ Value aper.OctetString([]byte) } -> slice header at offset 0 */
		bpf_probe_read_user(&oct_ptr, sizeof(oct_ptr), (void *)(naspdu_ptr + 0));
		bpf_probe_read_user(&oct_len, sizeof(oct_len), (void *)(naspdu_ptr + 8));
		if (!oct_ptr || oct_len <= 0)
			break;

		__u32 copy_len = oct_len > NAS_PDU_MAX ? NAS_PDU_MAX : (__u32)oct_len;

		bpf_probe_read_user(e->nas_pdu, copy_len, (void *)oct_ptr);
		e->nas_pdu_len = copy_len;
		break;
	}
}

SEC("uprobe")
int amf_ngap_disp(struct pt_regs *ctx)
{
	void *ran = (void *)GO_ARG1(ctx);
	void *message = (void *)GO_ARG2(ctx);

	if (!message)
		return 0;

	struct event_ngap *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	ZERO_EVENT(e);

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->probe_id = PROBE_NGAP_DISPATCH;
	e->ran_ptr = (__u64)ran;

	bpf_probe_read_user(&e->present, sizeof(e->present), (void *)((__u64)message + OFF_NGAPPDU_PRESENT));

	__u64 sub_ptr = ngap_submsg_ptr(message, e->present, &e->procedure_code);

	if (sub_ptr && e->present == NGAPPDU_PRESENT_INITIATING)
		ngap_copy_embedded_nas_pdu(e, sub_ptr, e->procedure_code);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ======================================================================== */
/* NAS: nas.Dispatch(ue *context.AmfUe, accessType models.AccessType,       */
/*                    procedureCode int64, msg *nas.Message) error          */
/* ======================================================================== */

/*
 * nas.Message (nas@v1.2.3/nas.go:12): SecurityHeader (embedded, 8B: uint8+
 * uint8+pad+uint32); *GmmMessage @ offset 8; *GsmMessage @ offset 16.
 * nas.GmmMessage (nas_generated.go:13): GmmHeader{Octet [3]uint8} embedded
 * at offset 0, then ~60 uniform *T pointers (RegistrationRequest, etc.).
 * GmmHeader.Octet[2] is the NAS MessageType byte (nas.go:64
 * GetMessageType() = a.Octet[2]) -- this alone is a universal discriminator
 * for every one of the ~60 possible NAS messages routed through Dispatch,
 * with no need to know each message's own field layout.
 */

#define OFF_NAS_MSG_GMM_PTR   8
#define OFF_GMMHDR_MSG_TYPE   2  /* GmmHeader.Octet[2] */
/* ACCESS_TYPE_MAX / struct event_nas: amf_func_load_events.h */

SEC("uprobe")
int amf_nas_disp(struct pt_regs *ctx)
{
	void *ue = (void *)GO_ARG1(ctx);
	__u64 access_type_ptr = GO_ARG2(ctx);
	__s64 access_type_len = (__s64)GO_ARG3(ctx);
	__s64 procedure_code = (__s64)GO_ARG4(ctx);
	void *msg = (void *)GO_ARG5(ctx);

	if (!msg)
		return 0;

	struct event_nas *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	ZERO_EVENT(e);

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->probe_id = PROBE_NAS_DISPATCH;
	e->ue_ptr = (__u64)ue;
	e->procedure_code = procedure_code;

	if (access_type_ptr && access_type_len > 0) {
		__u32 copy_len = access_type_len >= ACCESS_TYPE_MAX ? ACCESS_TYPE_MAX - 1 : (__u32)access_type_len;

		bpf_probe_read_user(e->access_type, copy_len, (void *)access_type_ptr);
	}

	__u64 gmm_ptr = 0;

	bpf_probe_read_user(&gmm_ptr, sizeof(gmm_ptr), (void *)((__u64)msg + OFF_NAS_MSG_GMM_PTR));
	if (gmm_ptr)
		bpf_probe_read_user(&e->message_type, sizeof(e->message_type),
				     (void *)(gmm_ptr + OFF_GMMHDR_MSG_TYPE));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ======================================================================== */
/* SBI: func (s *Server) HTTPXxx(c *gin.Context)                            */
/* ======================================================================== */

/*
 * At function entry the JSON request body hasn't been deserialized yet (each
 * handler does c.GetRawData() + openapi.Deserialize() itself, later in the
 * function body) -- see handler_list.txt. What IS already populated by gin's
 * router before the handler runs is the URL: method, path, and any :params
 * gin extracted from the route pattern. For 6 of these 7 hooks that path
 * param IS the operation's primary identifying IE (the target UE or
 * association), straight from the route table (internal/sbi/routes.go /
 * api_httpcallback.go / api_eventexposure.go):
 *   HTTPUEContextTransfer      /ue-contexts/:ueContextId/transfer
 *   HTTPN1N2MessageTransfer    /ue-contexts/:ueContextId/n1-n2-messages
 *   HTTPAmPolicyControlUpdateNotifyUpdate    /am-policy/:polAssoId/update
 *   HTTPAmPolicyControlUpdateNotifyTerminate /am-policy/:polAssoId/terminate
 *   HTTPSmContextStatusNotify  /smContextStatus/:supi/:pduSessionId (2 params)
 *   HTTPHandleDeregistrationNotification     /deregistration/:ueid
 *   HTTPCreateSubscription     /subscriptions   (no path param -- body-only IEs,
 *                               so this probe only captures method+path for it)
 *
 * gin.Context (gin@v1.10.0/context.go:55):
 *   responseWriter writermem (32B: embedded http.ResponseWriter iface(16) +
 *     size int(8) + status int(8)) @ offset 0
 *   Request *http.Request                          @ offset 32
 *   Writer  ResponseWriter (interface, 16B)         @ offset 40
 *   Params  Params([]Param)                         @ offset 56 (ptr/len/cap)
 * gin.Param (tree.go:24): Key string(16B); Value string(16B) -> 32B/elem.
 * net/http.Request (go1.26.2 src/net/http/request.go:113):
 *   Method string @ offset 0; URL *url.URL @ offset 16
 * net/url.URL (src/net/url/url.go:275): ... Path string @ offset 56
 */

#define OFF_GIN_CTX_REQUEST   32
#define OFF_GIN_CTX_PARAMS    56
#define OFF_HTTP_REQ_METHOD   0
#define OFF_HTTP_REQ_URL      16
#define OFF_URL_PATH          56
#define SZ_GIN_PARAM          32
#define OFF_GIN_PARAM_KEY     0
#define OFF_GIN_PARAM_VAL     16

/* METHOD_MAX/PATH_MAX/PKEY_MAX/PVAL_MAX / struct event_sbi: amf_func_load_events.h */

static __always_inline void read_go_str(void *dst, __u32 dst_max, __u64 str_hdr_addr)
{
	__u64 ptr = 0;
	__s64 len = 0;

	bpf_probe_read_user(&ptr, sizeof(ptr), (void *)str_hdr_addr);
	bpf_probe_read_user(&len, sizeof(len), (void *)(str_hdr_addr + 8));
	if (!ptr || len <= 0)
		return;
	__u32 copy_len = len >= dst_max ? dst_max - 1 : (__u32)len;

	bpf_probe_read_user(dst, copy_len, (void *)ptr);
}

static __always_inline void read_gin_param(__u64 params_ptr, __s64 params_len, int idx,
					    char *key_dst, __u32 key_max, char *val_dst, __u32 val_max)
{
	if (idx >= params_len)
		return;

	__u64 elem = params_ptr + (idx * SZ_GIN_PARAM);

	read_go_str(key_dst, key_max, elem + OFF_GIN_PARAM_KEY);
	read_go_str(val_dst, val_max, elem + OFF_GIN_PARAM_VAL);
}

/* Shared body for all 7 SBI hooks: gin.Context is GO_ARG2 (GO_ARG1 is the
 * *Server receiver) for every one of them, since they all share the plain
 * `func (s *Server) HTTPXxx(c *gin.Context)` shape. */
static __always_inline int emit_sbi_event(struct pt_regs *ctx, enum amf_probe_id probe_id)
{
	void *gctx = (void *)GO_ARG2(ctx);

	if (!gctx)
		return 0;

	struct event_sbi *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	ZERO_EVENT(e);

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->probe_id = probe_id;
	e->ctx_ptr = (__u64)gctx;

	__u64 req_ptr = 0;

	bpf_probe_read_user(&req_ptr, sizeof(req_ptr), (void *)((__u64)gctx + OFF_GIN_CTX_REQUEST));
	if (req_ptr) {
		read_go_str(e->method, METHOD_MAX, req_ptr + OFF_HTTP_REQ_METHOD);

		__u64 url_ptr = 0;

		bpf_probe_read_user(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + OFF_HTTP_REQ_URL));
		if (url_ptr)
			read_go_str(e->path, PATH_MAX, url_ptr + OFF_URL_PATH);
	}

	__u64 params_ptr = 0;
	__s64 params_len = 0;

	bpf_probe_read_user(&params_ptr, sizeof(params_ptr), (void *)((__u64)gctx + OFF_GIN_CTX_PARAMS + 0));
	bpf_probe_read_user(&params_len, sizeof(params_len), (void *)((__u64)gctx + OFF_GIN_CTX_PARAMS + 8));
	if (params_ptr && params_len > 0) {
		read_gin_param(params_ptr, params_len, 0, e->param0_key, PKEY_MAX, e->param0_val, PVAL_MAX);
		read_gin_param(params_ptr, params_len, 1, e->param1_key, PKEY_MAX, e->param1_val, PVAL_MAX);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* CONTEXT_LOOKUP <-> AMF: old-AMF side of Namf_ContextTransfer.
 * Param0 = ueContextId (the UE this instance is being asked to hand off). */
SEC("uprobe")
int amf_sbi_ue_xfer(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_UE_CTX_XFER);
}

/* SMF pushing NAS/N2 into SM_CONTEXT_PENDING -> INITIAL_CONTEXT_SETUP.
 * Param0 = ueContextId. */
SEC("uprobe")
int amf_sbi_n1n2(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_N1N2_XFER);
}

/* PCF Namf_EventExpose_Subscribe during POLICY_ASSOCIATING.
 * No path param on this route -- the subscribed event list is body-only,
 * so this probe only yields method+path; correlate with a processor-layer
 * hook if the subscribed UE/event filter is needed. */
SEC("uprobe")
int amf_sbi_sub_crt(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_SUB_CREATE);
}

/* PCF pushing a policy update. Param0 = polAssoId (the policy association). */
SEC("uprobe")
int amf_sbi_pol_upd(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_POLICY_UPDATE);
}

/* PCF pushing policy termination. Param0 = polAssoId. */
SEC("uprobe")
int amf_sbi_pol_trm(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_POLICY_TERM);
}

/* SMF async SM-context status. Param0 = supi, Param1 = pduSessionId. */
SEC("uprobe")
int amf_sbi_sm_ntfy(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_SM_STATUS);
}

/* UDM -> old-AMF deregistration notify (drives CLEANUP_REQUIRED).
 * Param0 = ueid. */
SEC("uprobe")
int amf_sbi_dereg(struct pt_regs *ctx)
{
	return emit_sbi_event(ctx, PROBE_SBI_DEREG_NOTIFY);
}

/* ======================================================================== */
/* SBI raw body: URETPROBE on github.com/gin-gonic/gin.(*Context).GetRawData */
/* ======================================================================== */

/*
 * The actual IEs of an SBI request are the JSON body, and that body does not
 * exist as a Go []byte until each handler reads it -- every one of the 7
 * HTTPXxx hooks above does `requestBody, err := c.GetRawData()` as its very
 * first statement (api_httpcallback.go:60,93,146,183; api_eventexposure.go:86;
 * api_communication.go:320-330ish,378), so gin.Context's own fields at
 * HTTPXxx *entry* can never expose it -- there is nothing nested to dig into
 * yet. GetRawData is gin's own method:
 *   func (c *Context) GetRawData() ([]byte, error) { return io.ReadAll(c.Request.Body) }
 * (gin@v1.10.0/context.go:906). It is the one shared chokepoint all SBI
 * bodies flow through, so a single uretprobe here -- mirroring how
 * ngap.dispatchMain/nas.Dispatch were picked as single chokepoints -- yields
 * the literal wire-format IEs for every SBI operation, not just the 7 marked
 * as important in handler_list.txt.
 *
 * NB: GetRawData is NOT limited to those 7 -- it's called by all ~35 SBI
 * handlers, so this probe alone can't tell you which endpoint a given body
 * belongs to. Read that off the corresponding amf_sbi_* entry event instead
 * (method/path/params) and correlate by nearest timestamp within the same
 * `pid` (TGID; this is a single-process AMF so that's mostly a sanity check,
 * not a real disambiguator). Exact correlation would need to key on the Go
 * *goroutine* id (from the runtime.g pointed to by TLS/fsbase, not the OS
 * tid bpf_get_current_pid_tgid() exposes), because io.ReadAll(Body) is a
 * blocking read and the calling goroutine can resume on a different OS
 * thread after it unblocks -- entry-vs-return TID matching across this
 * specific call is not reliable, which is why this is a return-only probe
 * with no attempt to pair itself back to an entry-side gin.Context pointer.
 *
 * Go ABIInternal result decomposition of ([]byte, error), reusing the same
 * amd64 register sequence as arguments (see GO_RETn comment above):
 *   RAX data ptr, RBX len, RCX cap, RDI error-itab, RSI error-data
 *
 * Loader note: this needs its own attach_target entry in amf_func_hooks.c
 * (retprobe: true, func_name: "github.com/gin-gonic/gin.(*Context).GetRawData")
 * -- it is not one of the 9 targets already declared there.
 */

/* SBI_BODY_MAX / IE_STR_MAX / struct event_sbi_body: amf_func_load_events.h */

/*
 * ---------------------------------------------------------------------------
 * Best-effort JSON IE extraction (analysis/amf_related_attacks.md "SBI /
 * HTTP-JSON" table, cross-referenced against the 7 request models in
 * doc/observe.md).
 *
 * amf_sbi_body has no per-endpoint identity (see the comment on the probe
 * below), so rather than deserializing a specific Go struct per handler this
 * scans the raw JSON text once for a fixed set of high-signal keys that are
 * each unique to (or unambiguous enough across) the 7 request bodies in
 * observe.md and copies out whichever are present:
 *
 *   "reason"          UeContextTransferReqData.Reason           (INIT_REG / MOBI_REG / MOBI_REG_UE_VALIDATED
 *                                                                 -- registration vs mobility handoff, CONTEXT_LOOKUP edge)
 *   "accessType"/      *.AccessType / StatusInfo.AnType /
 *   "anType"/           N1N2MessageTransferReqData.TargetAccess  (3GPP_ACCESS vs NON_3GPP_ACCESS)
 *   "targetAccess"
 *   "n1MessageClass"   N1MessageContainer.N1MessageClass         (5GMM/SM/LPP/SMS/UPDP/LCS -- what kind of NAS payload is riding along)
 *   "pduSessionId"     N1N2MessageTransferReqData.PduSessionId   (int; which PDU session this N1/N2 pair targets)
 *   "resourceStatus"   StatusInfo.ResourceStatus                 (ACTIVATED/RELEASED -- SmContextStatusNotify)
 *   "cause"            StatusInfo.Cause /
 *                       PcfAmPolicyControlTerminationNotification.Cause (release/termination reason; shared key name, harmless overlap)
 *   "deregReason"      DeregistrationData.DeregReason            (drives old-AMF CLEANUP_REQUIRED)
 *   "triggers"         PcfAmPolicyControlPolicyUpdate.Triggers   (first element only; e.g. SERV_AREA_CH)
 *   "supi"             AmfEventSubscription.Supi                 (subscription target UE)
 *   "nfId"             AmfEventSubscription.NfId                 (requester NF instance -- correlate against the
 *                                                                 Authorization-header capture below for the
 *                                                                 cross-service scope-bypass finding)
 *   "type"             AmfEvent.Type (eventList[0])              (LOCATION_REPORT/REGISTRATION_STATE_REPORT/...;
 *                                                                 ambiguous if another object earlier in the body also
 *                                                                 has a "type" key -- best effort only)
 *
 * This is NOT a JSON parser: no nesting/escaping awareness, first textual
 * match wins, and the scan window is capped at IE_SCAN_MAX bytes -- every key
 * above is a top-level field declared near the start of its Go struct (and
 * `encoding/json` emits fields in declaration order), so in every example
 * body shown in observe.md each key lands well inside that window even
 * though the full body can run longer (e.g. HTTPCreateSubscription's
 * eventList). Good enough to flag the state-transition-relevant IEs the
 * attack analysis calls out; anything more exact belongs in a userspace
 * consumer that actually runs openapi.Deserialize() equivalent logic against
 * the correlated amf_sbi_* entry-probe method+path.
 * ---------------------------------------------------------------------------
 */

#define IE_SCAN_MAX 256  /* bytes of body scanned for each key; every top-level
			  * key used below appears well inside this window in
			  * every example body in observe.md. */
#define IE_KEY_MAX  17   /* longest key literal below ("resourceStatus":, "n1MessageClass":), incl. quotes/colon */
/* IE_STR_MAX: amf_func_load_events.h (it's part of event_sbi_body's layout) */

struct find_key_ctx {
	const __u8 *body;
	__u32 body_len;
	const char *key;
	__u32 key_len;
	int found_pos; /* -1 until found_key_cb sets it */
};

/*
 * bpf_loop() callback for json_find_key() below. This used to be a
 * #pragma-unrolled `for (i = 0; i < IE_SCAN_MAX; i++)` loop with a nested
 * #pragma-unrolled key-compare loop inside it -- fully unrolled, that's
 * IE_SCAN_MAX * IE_KEY_MAX static branch instructions PER CALL SITE, and
 * sbi_parse_ies() below calls json_find_key() with 13 different keys, so
 * the whole thing multiplied out to tens of thousands of branches once
 * inlined into one probe. The kernel verifier rejected the result outright
 * ("The sequence of 8193 jumps is too complex") -- BPF_COMPLEXITY_LIMIT_
 * JMP_SEQ is a hard cap on path/branch complexity, independent of (and much
 * stricter than) the raw 1M-instruction limit.
 *
 * bpf_loop() (kernel >= 5.17) fixes this the standard way: the outer scan
 * becomes a genuine bounded RUNTIME loop around a single verified callback
 * subprogram, instead of IE_SCAN_MAX copies of the loop body baked into the
 * instruction stream. find_key_cb is deliberately NOT __always_inline --
 * bpf_loop() needs a real, single, callable BPF subprogram, and having only
 * one (parameterized via find_key_ctx, not per-key template expansion)
 * means its own small #pragma-unrolled inner key-compare loop (bounded by
 * IE_KEY_MAX, not IE_SCAN_MAX) is verified exactly once, not 13 times.
 */
static long find_key_cb(__u32 i, void *ctx)
{
	struct find_key_ctx *c = ctx;

	if (i >= IE_SCAN_MAX || i + c->key_len > c->body_len)
		return 1; /* stop -- past the scan window, or past the body itself */

	__u8 match = 1;

#pragma unroll
	for (__u32 j = 0; j < IE_KEY_MAX; j++) {
		if (j >= c->key_len)
			break;
		if (c->body[i + j] != (__u8)c->key[j]) {
			match = 0;
			break;
		}
	}
	if (match) {
		c->found_pos = (int)(i + c->key_len);
		return 1; /* stop -- found it */
	}
	return 0; /* keep scanning */
}

/* Returns the body offset right after a literal match of `key` (which should
 * include the surrounding quotes and trailing colon, e.g. "\"reason\":"), or
 * -1 if not found within the first IE_SCAN_MAX bytes of body. */
static __always_inline int json_find_key(const __u8 *body, __u32 body_len, const char *key, __u32 key_len)
{
	struct find_key_ctx ctx = {
		.body = body,
		.body_len = body_len,
		.key = key,
		.key_len = key_len,
		.found_pos = -1,
	};

	bpf_loop(IE_SCAN_MAX, find_key_cb, &ctx, 0);
	return ctx.found_pos;
}

/* Copies a JSON string value ("...") starting at/after `pos` (which may point
 * at a few bytes of whitespace before the opening quote) into dst.
 *
 * `pos` is a genuine runtime value (json_find_key's return, folded down from
 * many unrolled constant-return paths), unlike the compile-time-constant
 * loop indices used everywhere else in this file -- so unlike those, this
 * needs an explicit bound against the *array's* declared size (not just
 * body_len, which the verifier cannot assume stayed <= SBI_BODY_MAX across
 * the struct-field store/reload in sbi_parse_ies) before it's used in
 * body[pos + i], or the verifier cannot prove the access is in-bounds. */
static __always_inline void json_extract_str(const __u8 *body, __u32 body_len, __u32 pos, char *dst, __u32 dst_max)
{
	if (pos >= SBI_BODY_MAX - IE_STR_MAX - 8) /* headroom for the whitespace/quote skip below, plus the copy loop */
		return;

#pragma unroll
	for (int k = 0; k < 4; k++) {
		if (pos < body_len && (body[pos] == ' ' || body[pos] == '\t'))
			pos++;
	}
	if (pos >= body_len || body[pos] != '"')
		return;
	pos++;

	__u32 out = 0;

#pragma unroll
	for (__u32 i = 0; i < IE_STR_MAX; i++) {
		if (pos + i >= body_len)
			break;
		__u8 c = body[pos + i];

		if (c == '"')
			break;
		if (out < dst_max - 1)
			dst[out++] = (char)c;
	}
}

/* Parses a bare JSON integer (optional '-', then digits) starting at/after
 * `pos`. Only writes *out / sets *has_out when at least one digit was read,
 * so an absent field is distinguishable from a literal 0. */
static __always_inline void json_extract_int(const __u8 *body, __u32 body_len, __u32 pos, __s32 *out, __u8 *has_out)
{
	if (pos >= SBI_BODY_MAX - 24) /* see json_extract_str's comment on why this bound is needed */
		return;

#pragma unroll
	for (int k = 0; k < 4; k++) {
		if (pos < body_len && (body[pos] == ' ' || body[pos] == '\t'))
			pos++;
	}

	__s32 sign = 1;

	if (pos < body_len && body[pos] == '-') {
		sign = -1;
		pos++;
	}

	__s32 val = 0;
	__u8 got_digit = 0;

#pragma unroll
	for (__u32 i = 0; i < 10; i++) {
		if (pos + i >= body_len)
			break;
		__u8 c = body[pos + i];

		if (c < '0' || c > '9')
			break;
		val = val * 10 + (c - '0');
		got_digit = 1;
	}
	if (got_digit) {
		*out = val * sign;
		*has_out = 1;
	}
}

#define IE_STR_FIELD(body, len, lit, dst) \
	do { \
		int __pos = json_find_key((body), (len), (lit), sizeof(lit) - 1); \
		if (__pos >= 0) \
			json_extract_str((body), (len), (__u32)__pos, (dst), sizeof(dst)); \
	} while (0)

static __always_inline void sbi_parse_ies(struct event_sbi_body *e)
{
	const __u8 *body = e->body;
	__u32 len = e->body_len;

	IE_STR_FIELD(body, len, "\"reason\":", e->reason);

	IE_STR_FIELD(body, len, "\"accessType\":", e->access_type);
	if (e->access_type[0] == 0)
		IE_STR_FIELD(body, len, "\"anType\":", e->access_type);
	if (e->access_type[0] == 0)
		IE_STR_FIELD(body, len, "\"targetAccess\":", e->access_type);

	IE_STR_FIELD(body, len, "\"n1MessageClass\":", e->n1_message_class);
	IE_STR_FIELD(body, len, "\"resourceStatus\":", e->resource_status);
	IE_STR_FIELD(body, len, "\"cause\":", e->cause);
	IE_STR_FIELD(body, len, "\"deregReason\":", e->dereg_reason);
	IE_STR_FIELD(body, len, "\"supi\":", e->supi);
	IE_STR_FIELD(body, len, "\"nfId\":", e->nf_id);
	IE_STR_FIELD(body, len, "\"type\":", e->event_type0);

	int trig_pos = json_find_key(body, len, "\"triggers\":", sizeof("\"triggers\":") - 1);

	if (trig_pos >= 0) {
		__u32 p = (__u32)trig_pos;

		/* skip whitespace and the array's opening '[' before treating
		 * the first element like a plain string value */
#pragma unroll
		for (int k = 0; k < 4; k++) {
			if (p < len && (body[p] == ' ' || body[p] == '['))
				p++;
		}
		json_extract_str(body, len, p, e->trigger0, IE_STR_MAX);
	}

	int pdu_pos = json_find_key(body, len, "\"pduSessionId\":", sizeof("\"pduSessionId\":") - 1);

	if (pdu_pos >= 0)
		json_extract_int(body, len, (__u32)pdu_pos, &e->pdu_session_id, &e->has_pdu_session_id);
}

SEC("uretprobe")
int amf_sbi_body(struct pt_regs *ctx)
{
	__u64 data_ptr = GO_RET1(ctx);
	__s64 data_len = (__s64)GO_RET2(ctx);
	__u64 err_itab = GO_RET4(ctx);

	/* non-nil error (short read / closed conn) -> whatever ReadAll got back
	 * is incomplete; skip rather than emit a truncated/misleading body. */
	if (!data_ptr || data_len <= 0 || err_itab)
		return 0;

	struct event_sbi_body *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	ZERO_EVENT(e);

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->probe_id = PROBE_SBI_RAW_BODY;

	__u32 copy_len = data_len > SBI_BODY_MAX ? SBI_BODY_MAX : (__u32)data_len;

	bpf_probe_read_user(e->body, copy_len, (void *)data_ptr);
	e->body_len = copy_len;

	sbi_parse_ies(e);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ======================================================================== */
/* SBI Authorization header: net/http.(Header).Get("Authorization")         */
/* ======================================================================== */

/*
 * amf_related_attacks.md's top cross-cutting SBI finding is the free5GC
 * `VerifyOAuth` scope-check bypass (openapi/oauth/oauth.go): a Bearer token
 * minted for one NF, once it parses as a syntactically valid JWT, is
 * accepted regardless of whether its `scope` claim actually authorizes the
 * operation being called. Observing that requires seeing the raw
 * Authorization header the AMF received on each SBI call.
 *
 * gin.Context never exposes it as a plain string field the way method/path
 * are (see OFF_GIN_CTX_* above) -- it lives inside
 * gin.Context.Request.Header, a Go map[string][]string, and walking a live
 * Go runtime hmap from eBPF (bucket layout + the runtime's own hash seed)
 * is not something CO-RE/BTF can help with and is far too fragile to
 * hardcode. Instead this hooks the one function every header lookup in the
 * standard library funnels through -- gin's `c.GetHeader(key)` /
 * `c.requestHeader(key)` both bottom out in:
 *   func (h Header) Get(key string) string   (net/http/header.go)
 * -- the same "hook the stdlib chokepoint instead of decoding the type"
 * approach already used for gin.(*Context).GetRawData above. Header.Get is
 * called for many header names throughout the binary, so this pair of
 * probes only cares about calls where the key argument is literally
 * "Authorization"; the entry probe decides that and records intent to
 * capture in authz_probe_inflight keyed by the calling thread, and the
 * uretprobe reads the return string and clears it. Unlike GetRawData,
 * Header.Get does no blocking I/O, so it cannot be rescheduled onto a
 * different OS thread between entry and return -- the same-goroutine
 * assumption that made an inflight-by-tid map unsafe for GetRawData holds
 * fine here.
 *
 * Loader note: needs two attach_target entries in amf_func_hooks.c for
 * func_name "net/http.Header.Get" (value receiver -- no "(*Header)", unlike
 * the pointer-receiver gin.Context targets above) -- one retprobe:false
 * (prog_name amf_http_hdr_get_entry) and one retprobe:true (prog_name
 * amf_http_hdr_get_ret) attached to the same symbol.
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);   /* bpf_get_current_pid_tgid() of the calling thread */
	__type(value, __u8);
} authz_probe_inflight SEC(".maps");

#define AUTHZ_HDR_KEY   "Authorization"
/* AUTHZ_VAL_MAX / struct event_sbi_authz: amf_func_load_events.h */

SEC("uprobe")
int amf_http_hdr_get_entry(struct pt_regs *ctx)
{
	__u64 key_ptr = GO_ARG2(ctx);
	__s64 key_len = (__s64)GO_ARG3(ctx);

	if (key_len != (__s64)(sizeof(AUTHZ_HDR_KEY) - 1))
		return 0;

	char buf[sizeof(AUTHZ_HDR_KEY) - 1];

	if (bpf_probe_read_user(buf, sizeof(buf), (void *)key_ptr))
		return 0;

#pragma unroll
	for (int i = 0; i < (int)sizeof(buf); i++) {
		if (buf[i] != AUTHZ_HDR_KEY[i])
			return 0;
	}

	__u64 tid = bpf_get_current_pid_tgid();
	__u8 one = 1;

	bpf_map_update_elem(&authz_probe_inflight, &tid, &one, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int amf_http_hdr_get_ret(struct pt_regs *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	__u8 *pending = bpf_map_lookup_elem(&authz_probe_inflight, &tid);

	if (!pending)
		return 0;
	bpf_map_delete_elem(&authz_probe_inflight, &tid);

	__u64 val_ptr = GO_RET1(ctx);
	__s64 val_len = (__s64)GO_RET2(ctx);

	if (!val_ptr || val_len <= 0)
		return 0;

	struct event_sbi_authz *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	ZERO_EVENT(e);

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = tid >> 32;
	e->probe_id = PROBE_SBI_AUTHZ_HDR;

	__u32 copy_len = val_len >= AUTHZ_VAL_MAX ? AUTHZ_VAL_MAX - 1 : (__u32)val_len;

	bpf_probe_read_user(e->value, copy_len, (void *)val_ptr);
	e->value_len = copy_len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
