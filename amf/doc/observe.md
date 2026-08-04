# SBI request-body structures (the JSON `gin.Context` carries per handler)

For the 7 SBI hooks marked important in [handler_list.txt](handler_list.txt) /
instrumented in [amf_func_load.bpf.c](amf_func_load.bpf.c). `gin.Context`
itself never holds these fields (see the `amf_sbi_body` comment block in that
file) — each handler reads its own body via `c.GetRawData()` and deserializes
it into the Go model below via `openapi.Deserialize()`. This is exactly the
byte range `amf_sbi_body` (uretprobe on `gin.(*Context).GetRawData`) captures;
the per-endpoint `amf_sbi_*` entry probes capture the path params noted under
each route. Source: `github.com/free5gc/openapi@v1.2.5-.../models`.

---

## What `amf_func_load.bpf.c` does, program by program

12 BPF programs (`SEC("uprobe")`/`SEC("uretprobe")` functions), each a
uprobe/uretprobe on a Go symbol in the running AMF binary — attached per
`amf_func_hooks.c`'s `ngap_hook_funcs[]` / `nas_hook_funcs[]` /
`sbi_hook_funcs[]`. All 12 share one ring buffer (`events`,
`BPF_MAP_TYPE_RINGBUF`) and tag every record they emit with a `probe_id`
(`enum amf_probe_id`, `amf_func_load_events.h`) so a userspace consumer can
tell which program — and therefore which `struct event_*` shape — a given
ringbuf record is. Every program also runs `ZERO_EVENT(e)` on its reserved
ringbuf slot before filling it in, since `bpf_ringbuf_reserve()` hands back
raw (possibly stale) memory, not zeroed memory — see that macro's own
comment block for why it isn't a plain `memset()`.

### 1. `amf_ngap_disp` — NGAP dispatch

- **Hooks**: `github.com/free5gc/amf/internal/ngap.dispatchMain(ran *context.AmfRan, message *ngapType.NGAPPDU)`, uprobe (entry).
- **Reads**: `GO_ARG1`/`GO_ARG2` = `ran`/`message` pointers. Reads `message.Present` (offset 0) to find which of `InitiatingMessage`/`SuccessfulOutcome`/`UnsuccessfulOutcome` (offsets 8/16/24) is populated, then that sub-message's `ProcedureCode` (helper `ngap_submsg_ptr()`). If it's an `InitiatingMessage` carrying `InitialUEMessage` or `UplinkNASTransport` (procedure codes 15/46), `ngap_copy_embedded_nas_pdu()` walks the ASN.1 protocol-IE list (hand-derived offsets, bounded to `MAX_IE_SCAN`=12 IEs) to find and copy out the embedded NAS-PDU octet string.
- **Emits**: `event_ngap` (`PROBE_NGAP_DISPATCH`) — `ran_ptr`, `present`, `procedure_code`, `nas_pdu`/`nas_pdu_len`.
- **Why**: `dispatchMain` is the single chokepoint 100% of NGAP traffic funnels through (all ~30 procedure codes) — `procedure_code` is the baseline signal for sequencing/handover-bypass correlation (CVE-2026-42081/42082), and the embedded NAS-PDU is handed off for the NAS-side analysis below regardless of which NGAP procedure carried it.

### 2. `amf_nas_disp` — NAS dispatch

- **Hooks**: `github.com/free5gc/amf/internal/nas.Dispatch(ue *context.AmfUe, accessType models.AccessType, procedureCode int64, msg *nas.Message) error`, uprobe (entry).
- **Reads**: `GO_ARG1..5` = `ue` pointer, `accessType` string `{ptr,len}`, `procedureCode`, `msg` pointer. Copies `accessType`. Reads `msg.GmmMessage` (offset 8) then `GmmHeader.Octet[2]` (offset 2) — the NAS `MessageType` byte, a single-byte discriminator that covers all ~60 possible NAS messages without needing each one's own field layout.
- **Emits**: `event_nas` (`PROBE_NAS_DISPATCH`) — `ue_ptr`, `procedure_code`, `message_type`, `access_type`.
- **Why**: `Dispatch` is the single chokepoint for 100% of NAS traffic regardless of transport (N2-carried or SBI-replayed). `message_type` + `procedure_code` are exactly what's needed to validate state-transition legality per-UE — the core signal for every CoreCrisis finding (P1–P3, D1–D7 in [amf_related_attacks.md](amf_related_attacks.md)), all of which are illegal/out-of-order message-type or security-header-type transitions.

### 3–9. The 7 SBI entry probes

`amf_sbi_ue_xfer`, `amf_sbi_n1n2`, `amf_sbi_sub_crt`, `amf_sbi_pol_upd`,
`amf_sbi_pol_trm`, `amf_sbi_sm_ntfy`, `amf_sbi_dereg` — each is a one-line
wrapper around the shared helper `emit_sbi_event()`, differing only in
which `HTTPXxx` Go method it's attached to and which `probe_id` it passes.

- **Hooks**: `func (s *Server) HTTPXxx(c *gin.Context)`, uprobe (entry), for the 7 handlers marked `(X)` in [handler_list.txt](handler_list.txt).
- **Reads** (`emit_sbi_event()`): `GO_ARG2` = `*gin.Context` (`GO_ARG1` is the `*Server` receiver). From it: `Request` pointer (offset 32) → `Method` string (offset 0) and `URL` pointer (offset 16) → `Path` string (offset 56); and the `Params` slice (offset 56) → up to 2 `gin.Param{Key,Value}` pairs.
- **Emits**: `event_sbi` (one of `PROBE_SBI_UE_CTX_XFER` … `PROBE_SBI_DEREG_NOTIFY`) — `method`, `path`, `param0_key`/`param0_val`, `param1_key`/`param1_val`.
- **Why**: at handler *entry* the JSON body hasn't been deserialized yet (see `amf_sbi_body` below), but gin's router has already populated the URL and any `:params` — and for 6 of the 7, that path param *is* the operation's primary identifying IE straight from the route table:
  - `amf_sbi_ue_xfer` — CONTEXT_LOOKUP edge, `param0`=`ueContextId`
  - `amf_sbi_n1n2` — SM_CONTEXT_PENDING→INITIAL_CONTEXT_SETUP, `param0`=`ueContextId`
  - `amf_sbi_sub_crt` — POLICY_ASSOCIATING subscribe, no path param (body-only IEs — see `amf_sbi_body`)
  - `amf_sbi_pol_upd` / `amf_sbi_pol_trm` — policy update/termination, `param0`=`polAssoId`
  - `amf_sbi_sm_ntfy` — `param0`=`supi`, `param1`=`pduSessionId`
  - `amf_sbi_dereg` — drives CLEANUP_REQUIRED, `param0`=`ueid`

### 10. `amf_sbi_body` — raw SBI body + parsed IEs

- **Hooks**: `github.com/gin-gonic/gin.(*Context).GetRawData() ([]byte, error)`, **uretprobe** (fires at return) — the one shared chokepoint all ~35 SBI handlers' body reads funnel through, not just the 7 above.
- **Reads**: `GO_RET1..4` = data ptr/len/cap/error-itab; bails on a non-nil error. Copies up to `SBI_BODY_MAX`(1024) bytes of the raw JSON body. Then `sbi_parse_ies()` runs a bounded byte-literal scan (explicitly *not* a JSON parser) over the first `IE_SCAN_MAX`(256) bytes, looping over 5 fixed keys (`sbi_ie_keys[]`: `reason`, `accessType`, `cause`, `deregReason`, `nfId`) and copying out whichever are present.
  - The key search (`json_find_key()`/`find_key_cb()`) runs via `bpf_loop()` rather than a fully-unrolled loop — an earlier fully-unrolled version (13 keys × a full-window scan each) blew the verifier's jump-complexity limit ("The sequence of 8193 jumps is too complex"). Inside the callback, both the body window and the key literal are read with `bpf_probe_read_kernel()` rather than direct indexing, since the verifier doesn't carry a pointer's bound through the round trip into `bpf_loop()`'s callback `ctx`, even for memory the program legitimately owns.
- **Emits**: `event_sbi_body` (`PROBE_SBI_RAW_BODY`) — raw `body`/`body_len`, plus `reason`/`access_type`/`cause`/`dereg_reason`/`nf_id` (empty string = key not found).
- **Why**: this is where the actual wire-format IEs live — see the per-handler JSON schemas below; `gin.Context` at `HTTPXxx` entry never exposes them (the handler hasn't called `GetRawData()`/`Deserialize()` yet). Since it's one shared chokepoint for all ~35 SBI operations, a userspace consumer correlates a captured body back to its handler using the nearest-in-time `amf_sbi_*` entry-probe event (method + path) — see the [cross-reference table](#cross-reference-to-the-ebpf-capture) and [Parsed IE fields](#parsed-ie-fields-event_sbi_body-in-kernel-best-effort-json-scan) below for the full detail on both.

### 11–12. `amf_http_hdr_get_entry` / `amf_http_hdr_get_ret` — Authorization header capture

- **Hooks**: `net/http.Header.Get(key string) string` — **a pair** of probes (uprobe + uretprobe) on the *same* symbol, the stdlib chokepoint gin's `c.GetHeader()` / `c.Request.Header.Get()` bottom out through for every header lookup in the binary.
- **`amf_http_hdr_get_entry`** (uprobe): reads `GO_ARG2`/`GO_ARG3` = the `key` string `{ptr,len}`; bails immediately unless its length matches `"Authorization"`'s, then byte-compares the content. On a match, records the calling thread's `pid_tgid` in a small hash map (`authz_probe_inflight`) to arm the return-side probe.
- **`amf_http_hdr_get_ret`** (uretprobe): checks whether this thread is armed (looks itself up in, and removes itself from, `authz_probe_inflight`); if so, reads `GO_RET1`/`GO_RET2` = the returned string and copies up to `AUTHZ_VAL_MAX`(512) bytes.
- **Emits**: `event_sbi_authz` (`PROBE_SBI_AUTHZ_HDR`) — the raw `Bearer <jwt>` string.
- **Why**: the AMF-side tap for the top cross-cutting SBI finding in [amf_related_attacks.md](amf_related_attacks.md#included-with-caveats) — free5GC's `VerifyOAuth` silently accepts a token once it parses as a syntactically valid JWT, even if scope verification itself fails, so a token minted for one NF is accepted on every other NF's endpoints. A userspace consumer decodes the JWT `scope`/`iss` claims out-of-band and cross-checks them against the operation actually being called (`nf_id` from `amf_sbi_body`, method/path from the `amf_sbi_*` entry probes), correlating by nearest-in-time `pid` the same way raw bodies are.
- Entry/return correlation via a map (rather than the timestamp-based correlation `amf_sbi_body` needs) is safe here specifically because `Header.Get` does no blocking I/O, so entry and return always execute on the same OS thread — unlike `GetRawData()`, which can resume on a different thread after its blocking read.

---

## 1. HTTPUEContextTransfer

- **Route**: `POST /namf-comm/v1/ue-contexts/:ueContextId/transfer`
- **Entry probe**: `amf_sbi_ue_xfer` — `param0` = `ueContextId`
- **Handler**: `internal/sbi/api_communication.go:320`
- **Go type**: `models.UeContextTransferRequest`

```go
UeContextTransferRequest struct {
    JsonData            *UeContextTransferReqData `json:"jsonData"`
    BinaryDataN1Message []byte                    `json:"binaryDataN1Message,omitempty"` // multipart only
}

UeContextTransferReqData struct {
    Reason            TransferReason `json:"reason"`      // "INIT_REG" | "MOBI_REG" | "MOBI_REG_UE_VALIDATED"
    AccessType        AccessType     `json:"accessType"`   // "3GPP_ACCESS" | "NON_3GPP_ACCESS"
    PlmnId            *PlmnId        `json:"plmnId,omitempty"`
    RegRequest        *N1MessageContainer `json:"regRequest,omitempty"`
    SupportedFeatures string         `json:"supportedFeatures,omitempty"`
}

N1MessageContainer struct {          // RegRequest: the actual NAS Registration Request being handed off
    N1MessageClass   N1MessageClass   `json:"n1MessageClass"`   // "5GMM" | "SM" | "LPP" | "SMS" | "UPDP" | "LCS"
    N1MessageContent *RefToBinaryData `json:"n1MessageContent"` // {"contentId": "..."} -> multipart part = BinaryDataN1Message
    NfId              string          `json:"nfId,omitempty"`
    ServiceInstanceId string          `json:"serviceInstanceId,omitempty"`
}
```

Example wire body (`application/json`, no multipart NAS attachment):
```json
{
  "jsonData": {
    "reason": "MOBI_REG",
    "accessType": "3GPP_ACCESS",
    "plmnId": { "mcc": "208", "mnc": "93" }
  }
}
```
This is the CONTEXT_LOOKUP ⇄ AMF edge in `amf_state_machine.py` — `reason`
distinguishes initial vs. mobility registration, and `regRequest` (when
present, multipart) carries the actual NAS PDU being handed to the new AMF.

---

## 2. HTTPN1N2MessageTransfer

- **Route**: `POST /namf-comm/v1/ue-contexts/:ueContextId/n1-n2-messages`
- **Entry probe**: `amf_sbi_n1n2` — `param0` = `ueContextId`
- **Handler**: `internal/sbi/api_communication.go:374`
- **Go type**: `models.N1N2MessageTransferRequest` (multipart-only in this
  handler — pure `application/json` is explicitly rejected, see
  `api_communication.go:396`, because N1/N2 payloads are binary)

```go
N1N2MessageTransferRequest struct {
    JsonData                *N1N2MessageTransferReqData `json:"jsonData"`
    BinaryDataN1Message     []byte `json:"binaryDataN1Message,omitempty"`     // multipart part: the NAS PDU (e.g. DL NAS Transport payload)
    BinaryDataN2Information []byte `json:"binaryDataN2Information,omitempty"` // multipart part: the NGAP PDU (e.g. PDU session resource setup)
    BinaryMtData            []byte `json:"binaryMtData,omitempty"`
}

N1N2MessageTransferReqData struct {
    N1MessageContainer     *N1MessageContainer `json:"n1MessageContainer,omitempty"`
    N2InfoContainer        *N2InfoContainer    `json:"n2InfoContainer,omitempty"`
    MtData                 *RefToBinaryData    `json:"mtData,omitempty"`
    SkipInd                bool       `json:"skipInd,omitempty"`
    LastMsgIndication       bool       `json:"lastMsgIndication,omitempty"`
    PduSessionId            int32      `json:"pduSessionId,omitempty"`         // which PDU session this N1/N2 pair belongs to
    LcsCorrelationId        string     `json:"lcsCorrelationId,omitempty"`
    Ppi                     int32      `json:"ppi,omitempty"`
    Arp                     *Arp       `json:"arp,omitempty"`
    Var5qi                  int32      `json:"5qi,omitempty"`
    N1n2FailureTxfNotifURI  string     `json:"n1n2FailureTxfNotifURI,omitempty"`
    SmfReallocationInd      bool       `json:"smfReallocationInd,omitempty"`
    AreaOfValidity          *AreaOfValidity `json:"areaOfValidity,omitempty"`
    SupportedFeatures       string     `json:"supportedFeatures,omitempty"`
    OldGuami                *Guami     `json:"oldGuami,omitempty"`
    MaAcceptedInd            bool       `json:"maAcceptedInd,omitempty"`
    ExtBufSupport            bool       `json:"extBufSupport,omitempty"`
    TargetAccess             AccessType `json:"targetAccess,omitempty"`
    NfId                     string     `json:"nfId,omitempty"`
}

N2InfoContainer struct {
    N2InformationClass N2InformationClass `json:"n2InformationClass"` // "SM" | "NRPPa" | "PWS" | "PWS-BCAL" | "PWS-RF" | "RAN" | "V2X" | "PROSE"
    SmInfo    *N2SmInformation  `json:"smInfo,omitempty"`
    RanInfo   *N2RanInformation `json:"ranInfo,omitempty"`
    NrppaInfo *NrppaInformation `json:"nrppaInfo,omitempty"`
    PwsInfo   *PwsInformation   `json:"pwsInfo,omitempty"`
    V2xInfo   *V2xInformation   `json:"v2xInfo,omitempty"`
    ProseInfo *ProSeInformation `json:"proseInfo,omitempty"`
}
```

Example (SMF pushing a PDU Session Establishment Accept N1 SM message plus the
N2 resource-setup NGAP payload — this is the SM_CONTEXT_PENDING ->
INITIAL_CONTEXT_SETUP edge):
```json
{
  "jsonData": {
    "n1MessageContainer": {
      "n1MessageClass": "SM",
      "n1MessageContent": { "contentId": "n1msg" }
    },
    "n2InfoContainer": {
      "n2InformationClass": "SM",
      "smInfo": { "pduSessionId": 5, "n2InfoContent": { "ngapIeType": "PDU_RES_SETUP_REQ", "ngapData": { "contentId": "n2info" } } }
    },
    "pduSessionId": 5
  }
}
```
(`n1msg`/`n2info` multipart parts land in `BinaryDataN1Message` /
`BinaryDataN2Information` — the actual NAS/NGAP bytes.)

---

## 3. HTTPCreateSubscription

- **Route**: `POST /namf-evts/v1/subscriptions` (no path param — this is why
  `handler_list.txt` notes `amf_sbi_sub_crt` only yields method+path)
- **Handler**: `internal/sbi/api_eventexposure.go:83`
- **Go type**: `models.AmfCreateEventSubscription`

```go
AmfCreateEventSubscription struct {
    Subscription      *AmfEventSubscription `json:"subscription"`
    SupportedFeatures string                `json:"supportedFeatures,omitempty"`
    OldGuami          *Guami                `json:"oldGuami,omitempty"`
}

AmfEventSubscription struct {
    EventList           []AmfEvent `json:"eventList"`           // what PCF wants notified about
    EventNotifyUri      string     `json:"eventNotifyUri"`      // callback URL for Namf_EventExposure_Notify
    NotifyCorrelationId string     `json:"notifyCorrelationId"`
    NfId                 string     `json:"nfId"`
    SubsChangeNotifyUri            string `json:"subsChangeNotifyUri,omitempty"`
    SubsChangeNotifyCorrelationId  string `json:"subsChangeNotifyCorrelationId,omitempty"`
    Supi                string   `json:"supi,omitempty"`         // the UE this subscription targets (when not AnyUE)
    GroupId             string   `json:"groupId,omitempty"`
    ExcludeSupiList     []string `json:"excludeSupiList,omitempty"`
    ExcludeGpsiList     []string `json:"excludeGpsiList,omitempty"`
    IncludeSupiList     []string `json:"includeSupiList,omitempty"`
    IncludeGpsiList     []string `json:"includeGpsiList,omitempty"`
    Gpsi                string   `json:"gpsi,omitempty"`
    Pei                 string   `json:"pei,omitempty"`
    AnyUE               bool     `json:"anyUE,omitempty"`
    Options             *AmfEventMode         `json:"options,omitempty"`
    SourceNfType        NrfNfManagementNfType `json:"sourceNfType,omitempty"`
}

AmfEvent struct {          // one element of EventList
    Type                  AmfEventType    `json:"type"`  // e.g. "LOCATION_REPORT", "REGISTRATION_STATE_REPORT", "COMMUNICATION_FAILURE_REPORT"
    ImmediateFlag         bool            `json:"immediateFlag,omitempty"`
    AreaList              []AmfEventArea  `json:"areaList,omitempty"`
    LocationFilterList    []LocationFilter `json:"locationFilterList,omitempty"`
    RefId                 int32           `json:"refId,omitempty"`
    ReportUeReachable     bool            `json:"reportUeReachable,omitempty"`
    MaxReports            int32           `json:"maxReports,omitempty"`
    MaxResponseTime       int32           `json:"maxResponseTime,omitempty"`
    MinInterval           int32           `json:"minInterval,omitempty"`
    // ... (TargetArea, SnssaiFilter, UeInAreaFilter, DispersionArea, etc.)
}
```

Example (matches registration-doc step 62 — PCF subscribing right after
policy association, POLICY_ASSOCIATING state):
```json
{
  "subscription": {
    "eventList": [
      { "type": "LOCATION_REPORT" },
      { "type": "REGISTRATION_STATE_REPORT" },
      { "type": "COMMUNICATION_FAILURE_REPORT" }
    ],
    "eventNotifyUri": "https://pcf.example/npcf-am-policy-control/v1/notify",
    "notifyCorrelationId": "sub-42",
    "nfId": "6bd... (PCF instance UUID)",
    "supi": "imsi-208930000000001"
  }
}
```

---

## 4. HTTPAmPolicyControlUpdateNotifyUpdate

- **Route**: `POST /namf-callback/v1/am-policy/:polAssoId/update`
- **Entry probe**: `amf_sbi_pol_upd` — `param0` = `polAssoId`
- **Handler**: `internal/sbi/api_httpcallback.go:57`
- **Go type**: `models.PcfAmPolicyControlPolicyUpdate`

```go
PcfAmPolicyControlPolicyUpdate struct {
    ResourceUri   string                              `json:"resourceUri"`
    Triggers      []PcfAmPolicyControlRequestTrigger   `json:"triggers,omitempty"`   // e.g. "LOC_CH", "PRA_CH", "SERV_AREA_CH"
    ServAreaRes   *ServiceAreaRestriction               `json:"servAreaRes,omitempty"`
    WlServAreaRes *WirelineServiceAreaRestriction        `json:"wlServAreaRes,omitempty"`
    Rfsp          int32   `json:"rfsp,omitempty"`
    TargetRfsp    int32   `json:"targetRfsp,omitempty"`
    SmfSelInfo    *SmfSelectionData `json:"smfSelInfo,omitempty"`
    UeAmbr        *Ambr             `json:"ueAmbr,omitempty"`
    UeSliceMbrs   []*UeSliceMbr     `json:"ueSliceMbrs,omitempty"`
    Pras          map[string]*PresenceInfoRm `json:"pras,omitempty"`
    PcfUeInfo     *PcfUeCallbackInfo `json:"pcfUeInfo,omitempty"`
    MatchPdus     []PduSessionInfo   `json:"matchPdus,omitempty"`
    AsTimeDisParam *PcfAmPolicyControlAsTimeDistributionParam `json:"asTimeDisParam,omitempty"`
}
```

Example (PCF revising the UE-AMBR / RFSP mid-association —
POLICY_ASSOCIATING/REGISTERED_CONNECTED edge):
```json
{
  "resourceUri": "https://pcf.example/npcf-am-policy-control/v1/policies/42",
  "triggers": ["SERV_AREA_CH"],
  "rfsp": 3,
  "ueAmbr": { "uplink": "50 Mbps", "downlink": "100 Mbps" }
}
```

---

## 5. HTTPAmPolicyControlUpdateNotifyTerminate

- **Route**: `POST /namf-callback/v1/am-policy/:polAssoId/terminate`
- **Entry probe**: `amf_sbi_pol_trm` — `param0` = `polAssoId`
- **Handler**: `internal/sbi/api_httpcallback.go:90`
- **Go type**: `models.PcfAmPolicyControlTerminationNotification`

```go
PcfAmPolicyControlTerminationNotification struct {
    ResourceUri string                        `json:"resourceUri"`
    Cause       PolicyAssociationReleaseCause `json:"cause"` // "UNSPECIFIED" | "UE_SUBSCRIPTION" | "INSUFFICIENT_RES"
}
```

Smallest body of the 7 — just enough to tell the AMF *which* policy
association died and *why*:
```json
{ "resourceUri": "https://pcf.example/npcf-am-policy-control/v1/policies/42", "cause": "UE_SUBSCRIPTION" }
```

---

## 6. HTTPSmContextStatusNotify

- **Route**: `POST /namf-callback/v1/smContextStatus/:supi/:pduSessionId`
- **Entry probe**: `amf_sbi_sm_ntfy` — `param0` = `supi`, `param1` = `pduSessionId`
  (note: unlike the other 6, the primary identifying IEs here are already
  fully resolved in the URL, not just an opaque association ID)
- **Handler**: `internal/sbi/api_httpcallback.go:143`
- **Go type**: `models.SmfPduSessionSmContextStatusNotification`

```go
SmfPduSessionSmContextStatusNotification struct {
    StatusInfo                        *StatusInfo          `json:"statusInfo"`
    SmallDataRateStatus                *SmallDataRateStatus `json:"smallDataRateStatus,omitempty"`
    ApnRateStatus                      *ApnRateStatus       `json:"apnRateStatus,omitempty"`
    DdnFailureStatus                   bool     `json:"ddnFailureStatus,omitempty"`
    NotifyCorrelationIdsForddnFailure  []string `json:"notifyCorrelationIdsForddnFailure,omitempty"`
    NewIntermediateSmfId string `json:"newIntermediateSmfId,omitempty"`
    NewSmfId              string `json:"newSmfId,omitempty"`
    NewSmfSetId            string `json:"newSmfSetId,omitempty"`
    OldSmfId                string `json:"oldSmfId,omitempty"`
    OldSmContextRef          string `json:"oldSmContextRef,omitempty"`
    AltAnchorSmfUri           string `json:"altAnchorSmfUri,omitempty"`
    AltAnchorSmfId             string `json:"altAnchorSmfId,omitempty"`
    TargetDnaiInfo *TargetDnaiInfo `json:"targetDnaiInfo,omitempty"`
    OldPduSessionRef  string `json:"oldPduSessionRef,omitempty"`
    InterPlmnApiRoot   string `json:"interPlmnApiRoot,omitempty"`
}

StatusInfo struct {
    ResourceStatus    ResourceStatus     `json:"resourceStatus"` // "ACTIVATED" | "RELEASED" | ...
    Cause             SmfPduSessionCause `json:"cause,omitempty"` // release reason, when ResourceStatus == RELEASED
    CnAssistedRanPara *CnAssistedRanPara `json:"cnAssistedRanPara,omitempty"`
    AnType            AccessType         `json:"anType,omitempty"`
}
```

Example (this is the "SMF async status feeding PDU_SESSION_REJECTED /
cleanup" edge from `handler_list.txt`):
```json
{
  "statusInfo": {
    "resourceStatus": "RELEASED",
    "cause": "REL_DUE_TO_DUPLICATE_SESSION_ID",
    "anType": "3GPP_ACCESS"
  }
}
```

---

## 7. HTTPHandleDeregistrationNotification

- **Route**: `POST /namf-callback/v1/deregistration/:ueid`
- **Entry probe**: `amf_sbi_dereg` — `param0` = `ueid`
- **Handler**: `internal/sbi/api_httpcallback.go:177`
- **Go type**: `models.DeregistrationData`

```go
DeregistrationData struct {
    DeregReason      DeregistrationReason `json:"deregReason"`
    // "UE_INITIAL_REGISTRATION" | "UE_REGISTRATION_AREA_CHANGE" | "SUBSCRIPTION_WITHDRAWN" |
    // "5GS_TO_EPS_MOBILITY" | "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION" |
    // "REREGISTRATION_REQUIRED" | "SMF_CONTEXT_TRANSFERRED"
    AccessType       AccessType `json:"accessType,omitempty"`
    PduSessionId     int32      `json:"pduSessionId,omitempty"`
    NewSmfInstanceId string     `json:"newSmfInstanceId,omitempty"`
}
```

Example (UDM telling the OLD AMF to drop this UE because a new AMF just
registered it elsewhere — registration-doc step 56, the CLEANUP_REQUIRED
trigger):
```json
{ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" }
```

---

## Cross-reference to the eBPF capture

| # | Handler | Entry probe (path IE) | Raw body captured by |
|---|---|---|---|
| 1 | HTTPUEContextTransfer | `amf_sbi_ue_xfer` (`ueContextId`) | `amf_sbi_body` |
| 2 | HTTPN1N2MessageTransfer | `amf_sbi_n1n2` (`ueContextId`) | `amf_sbi_body` |
| 3 | HTTPCreateSubscription | `amf_sbi_sub_crt` (none) | `amf_sbi_body` |
| 4 | HTTPAmPolicyControlUpdateNotifyUpdate | `amf_sbi_pol_upd` (`polAssoId`) | `amf_sbi_body` |
| 5 | HTTPAmPolicyControlUpdateNotifyTerminate | `amf_sbi_pol_trm` (`polAssoId`) | `amf_sbi_body` |
| 6 | HTTPSmContextStatusNotify | `amf_sbi_sm_ntfy` (`supi`, `pduSessionId`) | `amf_sbi_body` |
| 7 | HTTPHandleDeregistrationNotification | `amf_sbi_dereg` (`ueid`) | `amf_sbi_body` |

`amf_sbi_body` is a single shared uretprobe (see `amf_func_load.bpf.c`), so it
fires for all ~35 SBI operations, not just these 7 — a userspace consumer
identifies which JSON schema from this file applies to a given captured body
by correlating with the nearest-in-time entry-probe event (method + path),
per the caveat already documented there.

## Parsed IE fields (`event_sbi_body`, in-kernel best-effort JSON scan)

Cross-referenced against [amf_related_attacks.md](amf_related_attacks.md)'s
"Information Elements to Observe for Detection" / SBI table.
`amf_sbi_body` no longer just copies the raw body — it also runs a bounded,
key-literal byte scan (`sbi_parse_ies()` in `amf_func_load.bpf.c`) over the
first 256 bytes (`IE_SCAN_MAX`) for a deliberately narrow set of 5 keys
(`sbi_ie_keys[]`, looped over rather than one hand-written call site per
key) and fills these fields whenever the corresponding JSON key is present
(empty string means "not found", not "empty value"):

| `event_sbi_body` field | JSON key | Source model.field | Relevant finding |
|---|---|---|---|
| `reason` | `reason` | `UeContextTransferReqData.Reason` | distinguishes INIT_REG vs MOBI_REG at the CONTEXT_LOOKUP edge |
| `access_type` | `accessType` | `*.AccessType` | cross-checked against NAS-side access type for spoofed-transport detection |
| `cause` | `cause` | `StatusInfo.Cause`, `PcfAmPolicyControlTerminationNotification.Cause` | release/termination reason (shared key name across two handlers, harmless overlap) |
| `dereg_reason` | `deregReason` | `DeregistrationData.DeregReason` | drives old-AMF CLEANUP_REQUIRED |
| `nf_id` | `nfId` | `AmfEventSubscription.NfId` | requester NF instance — correlate against the Authorization capture below for the cross-service scope-bypass finding |

An earlier version of this also captured `n1MessageClass`, `pduSessionId`,
`resourceStatus`, `triggers[0]`, `supi`, and `eventList[0].type` — trimmed
back to these 5 to keep `sbi_parse_ies()` a simple loop instead of one
call site per key; add a row to `sbi_ie_keys[]`/`event_sbi_body` if one of
those becomes load-bearing again.

This is a byte-literal scan, not a JSON parser: no nesting/escaping
awareness, first textual match wins within the 256-byte window (every key
above is a top-level, early-declared field, so it lands inside that window
in each example body even when the full body runs longer). It is meant
to surface the specific IEs the attack analysis calls out cheaply, in-kernel
— not to replace a real `openapi.Deserialize()`-equivalent in a userspace
consumer that also needs full-fidelity fields.

## Authorization header capture (`event_sbi_authz`)

New probe pair `amf_http_hdr_get_entry` / `amf_http_hdr_get_ret`, hooking
`net/http.Header.Get` (entry + uretprobe) and filtering for calls where the
`key` argument is literally `"Authorization"`. This is the AMF-side tap for
the cross-cutting SBI finding in
[amf_related_attacks.md](amf_related_attacks.md#included-with-caveats):
`VerifyOAuth` (`openapi/oauth/oauth.go`) silently returns success when only
scope verification fails but the JWT parses cleanly, so a token minted for
one NF is accepted on every other NF's endpoints, including AMF's Namf_*
APIs. Emits `event_sbi_authz{ ts_ns, pid, probe_id=PROBE_SBI_AUTHZ_HDR,
value_len, value[512] }` — the raw `Bearer <jwt>` string. A userspace
consumer decodes the JWT `scope`/`iss` claims out-of-band (no JSON/base64
decoding is attempted in-kernel) and correlates by nearest-in-time `pid`
against the matching `amf_sbi_*` entry-probe event, the same way raw bodies
are correlated to their handler.

gin.Context's own fields were not used for this (unlike `method`/`path`
above) because the header lives in a Go `map[string][]string`
(`Request.Header`), and walking a live Go runtime hashmap from eBPF has no
CO-RE/BTF support and no stable, portable layout to hardcode — see the
`amf_http_hdr_get_*` comment block in `amf_func_load.bpf.c` for the full
rationale.
