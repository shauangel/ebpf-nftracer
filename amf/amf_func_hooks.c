#include "../common.h"

/*  Interface uprobe targets - group per ingress interface (NGAP, NAS, SBI)  */

/* ── NGAP: N2, gNB -> AMF (SCTP) ── */

// Can remove if we do sctp parse in xdp_ngap
struct attach_target ngap_hook_funcs[] = {
    {
        .prog_name = "amf_ngap_disp",
        .func_name = "github.com/free5gc/amf/internal/ngap.dispatchMain",
        .retprobe = false,
        .link = NULL,
    },
};
int ngap_hook_funcs_cnt = sizeof(ngap_hook_funcs) / sizeof(ngap_hook_funcs[0]);

/* ── NAS: UE -> AMF (NGAP NAS-PDU, SBI N1MessageNotify) ── */

struct attach_target nas_hook_funcs[] = {
    {
        .prog_name = "amf_nas_disp",
        .func_name = "github.com/free5gc/amf/internal/nas.Dispatch",
        .retprobe = false,
        .link = NULL,
    },
};
int nas_hook_funcs_cnt = sizeof(nas_hook_funcs) / sizeof(nas_hook_funcs[0]);

/* ── SBI: NFs -> AMF (HTTP/JSON) ── */

struct attach_target sbi_hook_funcs[] = {
    {
        /* CONTEXT_LOOKUP <-> AMF: inbound side of Namf_ContextTransfer
         * when this instance is the OLD AMF.
         * binary/doc: api_communication.go:320 */
        .prog_name = "amf_sbi_ue_xfer",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPUEContextTransfer",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* SMF pushing NAS/N2 into SM_CONTEXT_PENDING -> INITIAL_CONTEXT_SETUP.
         * binary/doc: api_communication.go:374 */
        .prog_name = "amf_sbi_n1n2",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPN1N2MessageTransfer",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* PCF Namf_EventExpose_Subscribe during POLICY_ASSOCIATING.
         * binary/doc: api_eventexposure.go:83 */
        .prog_name = "amf_sbi_sub_crt",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPCreateSubscription",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* PCF pushing policy changes affecting POLICY_ASSOCIATING /
         * REGISTERED_CONNECTED.
         * binary/doc: api_httpcallback.go:57 */
        .prog_name = "amf_sbi_pol_upd",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPAmPolicyControlUpdateNotifyUpdate",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* PCF pushing policy termination, same edge as above.
         * binary/doc: api_httpcallback.go:90 */
        .prog_name = "amf_sbi_pol_trm",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPAmPolicyControlUpdateNotifyTerminate",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* SMF async status feeding PDU_SESSION_REJECTED / cleanup.
         * binary/doc: api_httpcallback.go:143 */
        .prog_name = "amf_sbi_sm_ntfy",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPSmContextStatusNotify",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* UDM->Old AMF deregistration notify driving old-AMF
         * CLEANUP_REQUIRED.
         * binary/doc: api_httpcallback.go:177 */
        .prog_name = "amf_sbi_dereg",
        .func_name = "github.com/free5gc/amf/internal/sbi.(*Server).HTTPHandleDeregistrationNotification",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* Shared chokepoint for every SBI handler's raw JSON request body
         * (all ~35, not just the 7 above) -- uretprobe, see the amf_sbi_body
         * comment block in amf_func_load.bpf.c. */
        .prog_name = "amf_sbi_body",
        .func_name = "github.com/gin-gonic/gin.(*Context).GetRawData",
        .retprobe = true,
        .link = NULL,
    },
    {
        /* Entry half of the Authorization-header capture pair -- decides
         * whether this Header.Get call is for "Authorization" and, if so,
         * arms amf_http_hdr_get_ret. See the amf_http_hdr_get_* comment
         * block in amf_func_load.bpf.c. */
        .prog_name = "amf_http_hdr_get_entry",
        .func_name = "net/http.Header.Get",
        .retprobe = false,
        .link = NULL,
    },
    {
        /* Return half of the Authorization-header capture pair. */
        .prog_name = "amf_http_hdr_get_ret",
        .func_name = "net/http.Header.Get",
        .retprobe = true,
        .link = NULL,
    },
};
int sbi_hook_funcs_cnt = sizeof(sbi_hook_funcs) / sizeof(sbi_hook_funcs[0]);
