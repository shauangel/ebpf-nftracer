# AMF-Related Attacks

only rows where the **AMF** (or its
NAS-terminating role, which is AMF-owned regardless of which 5GC distro is named)
is the affected component. 

| CVE | Impact | AMF Component / Interface | Description | Patch / Issue | Source |
|---|---|---|---|---|---|
| CVE-2024-33241 ⚠️ reserved | Authentication bypass | OAI-CN-5G AMF, NAS (P2) | Plaintext `SecurityModeComplete` accepted before any `AuthenticationResponse` arrives; AMF replies with plaintext `RegistrationAccept`, completing registration with **no authentication**. Enables impersonation, billing fraud, mass zombie-registration DoS. Violates TS 24.501. | Not public — GitLab EURECOM | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| CVE-2026-42081, CVE-2026-42082 | Handover authentication bypass | free5GC AMF, NGAP / NAS | UE security capabilities bypassed on NGAP `PathSwitchRequest`; concurrent NAS Security Mode Command validation missing during NGAP handover. Same territory as CoreCrisis P2 but on the handover path. | [GHSA-77x9-rf64-92gv](https://github.com/advisories/GHSA-77x9-rf64-92gv) · [GHSA-vrrx-58h3-prmh](https://github.com/advisories/GHSA-vrrx-58h3-prmh) | GitHub Advisory DB · credited to Kookmin University |
| — none | Identity spoofing | free5GC AMF, NAS (P3) | No validation of IMEI/IMEISV length or checksum during registration. Bypasses operator IMEI blacklists, enables injection into IMEI-keyed downstream systems, privilege escalation where IMEI gates access. | [free5gc issue 624](https://github.com/free5gc/free5gc/issues/624) | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| CVE-2024-33233 ⚠️ reserved | Protocol violation → DoS | Open5GS AMF, NAS (P1) | Sink state: AMF deletes `AMF_UE_NGAP_ID` on receiving a NAS message in an invalid state, permanently wedging the UE context. | [open5gs issue 3131](https://github.com/open5gs/open5gs/issues/3131) | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D1) | Open5GS, OAI-CN-5G AMF, NAS | `IdentityResponse` with no preceding `RegistrationRequest` still triggers `AuthenticationRequest`. TS 24.501 allows only `RegistrationRequest` to leave 5GMM-DEREGISTERED. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D2) | free5GC, OAI-CN-5G AMF, NAS | Responds to messages carrying an invalid Security Header Type of 5 or greater. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D3) | Open5GS, OAI-CN-5G, Amarisoft AMF, NAS | Accepts protected messages before `SecurityModeComplete`. free5GC does not. Traced to ambiguity in TS 24.501 §4.4.2.5 / §5.4.2.1. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D4) | Open5GS, OAI-CN-5G AMF, NAS | Accepts the wrong Security Header Type inside a `SecurityModeComplete` message. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D5) | Open5GS, free5GC, OAI-CN-5G, Amarisoft AMF, NAS | Accepts integrity-protected-only messages when the negotiated algorithm requires both integrity protection and ciphering. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D6) | Open5GS, free5GC, OAI-CN-5G, Amarisoft AMF, NAS | Responds to protected messages carrying the wrong Security Header Type. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |
| — none | Spec deviation (D7) | Open5GS, OAI-CN-5G AMF, NAS | Responds to plaintext messages carrying the wrong Security Header Type. | — | [CoreCrisis · USENIX Sec '25](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) |

## Included with caveats (NF not exclusively AMF, but AMF is in scope)

| CVE | Impact | Component / Interface | Description | Source |
|---|---|---|---|---|
| — pending | Cross-service authorization bypass | free5GC, **all NFs via NRF** (incl. AMF), SBI | `VerifyOAuth` in `openapi/oauth/oauth.go` wraps the error from `jwt.ParseWithClaims`, not from `verifyScope`; when scope verification fails but the JWT parses cleanly, the wrapped error is `nil` and the call returns success. A token issued for one service is accepted by every other service — including Namf_* APIs. | [FivGeeFuzz · preprint](https://arxiv.org/abs/2509.08992) |
| CVE requested | Improper authentication → DoS | free5GC (NF unspecified) | "Improper authentication reachable in the **registered state**, leading to denial of service." No further detail given, but 5GMM-REGISTERED is an AMF NAS state — likely AMF-adjacent. | [5GC-Fuzz · IEEE INFOCOM '25](https://ieeexplore.ieee.org/document/11044489) |


# Information Elements to Observe for Detection

Derived from the AMF attack list above, cross-referenced against the ingress
chokepoints in [handler_list.txt](handler_list.txt) (`ngap.dispatchMain`,
`nas.Dispatch`, and the 35 SBI handlers). Grouped by interface, since that's
where each element becomes a typed/decoded field and is cheapest to hook.

## NGAP / N2 (`ngap.dispatchMain`)

| Element | Why it matters |
|---|---|
| **Procedure Code / message type** (InitialUEMessage, UplinkNASTransport, PathSwitchRequest, HandoverRequired, PDUSessionResourceSetupResponse, …) | Baseline signal for sequencing and rate anomalies; needed to correlate with the handover-bypass CVEs (CVE-2026-42081/42082). |
| **AMF_UE_NGAP_ID / RAN_UE_NGAP_ID** | Pairing/lifecycle tracking; CVE-2024-33233 is a sink state from premature deletion of this ID — must observe create/delete/rebind events per ID. |
| **UE Security Capabilities IE** | CVE-2026-42081/42082: bypassed on `PathSwitchRequest` — must diff the capability set carried at handover against the one negotiated at initial registration. |
| **Source/Target ToAMF / ToRAN Container** (handover) | Carries forwarded security context; needed to detect missing concurrent NAS Security Mode Command validation during handover. |
| **Embedded NAS-PDU** | Pass-through payload — must be handed to the NAS observer below regardless of NGAP procedure. |

## NAS / GMM (`nas.Dispatch`)

| Element | Why it matters |
|---|---|
| **Message Type / procedure code** (RegistrationRequest, IdentityResponse, AuthenticationRequest/Response, SecurityModeCommand/Complete, RegistrationAccept, Deregistration) | Core signal for every CoreCrisis finding (P1–P3, D1–D7): all are illegal or out-of-order message-type transitions. |
| **Security Header Type** (0=plaintext, 1=integrity-protected, 2=integrity+ciphered, 3/4=new-context variants) | Directly targeted by D2, D4, D6, D7 (wrong/invalid header type accepted or responded to) and CVE-2024-33241 (plaintext accepted where ciphered is required). |
| **5GMM mobility-management state** (DEREGISTERED, REGISTRATION-INITIATED, SECURITY-MODE-CONTROL-INITIATED, REGISTERED, …) at time of message arrival | Needed to validate every state-transition legality check (D1, D3, D5, P1). Must be tracked per-UE as a state machine, not read off the wire — it's derived from message history. |
| **MAC (message authentication code) value + verification result** | Distinguishes "integrity-protected" claims from actual proof; needed for D3/D5/D6 (accepted despite missing/invalid integrity protection). |
| **NAS Sequence Number / NAS COUNT** | Replay and reordering detection; underpins ciphering/integrity validation for all Security Header Type checks. |
| **Mobile Identity IE** (SUCI / SUPI / GUTI / **IMEI / IMEISV**) — length, format, checksum | CVE identity-spoofing finding: AMF accepts malformed IMEI/IMEISV with no length or Luhn-checksum validation. |
| **ngKSI / Key Set Identifier** | Ties AuthenticationResponse/SecurityModeComplete back to the correct security context; relevant to CVE-2024-33241's out-of-order acceptance. |

## SBI / HTTP-JSON (35 handlers in `internal/sbi/api_*.go`)

| Element | Why it matters |
|---|---|
| **Authorization: Bearer token — `scope` claim vs. target NF/operation** | Cross-service auth bypass: `VerifyOAuth` silently returns success when only scope verification (not JWT parsing) fails. Must independently re-check requested scope against the operation being called, not trust the handler's own gate. |
| **NF Instance ID / requester identity (issuer of the token)** | Needed to detect a token minted for one NF being replayed against Namf_* endpoints. |
| **HTTP operation identity** (which of the 35 handlers, e.g. `HTTPN1N2MessageTransfer`, `HTTPUEContextTransfer`, `HTTPCreateSubscription`) | Establishes the expected scope/audience baseline per the table above, and flags calls to the (X)-marked state-transition handlers out of registration-FSM order. |
| **Referenced context ID in body** (e.g. `AMF_UE_NGAP_ID`/`supi` inside `N1N2MessageTransfer`, `ueContextTransfer` requests) | Correlates SBI-triggered state changes back to the same per-UE state machine tracked on the NAS side, closing the loop between the "improper auth in registered state → DoS" report and a concrete UE context. |

### Cross-cutting

All of the above ultimately funnel into a **per-UE state machine** (5GMM state
+ AMF_UE_NGAP_ID/RAN_UE_NGAP_ID lifecycle + last-seen ngKSI/security context),
since nearly every AMF-specific finding above is a violation of *expected
transition given current state*, not a malformed single message. Any eBPF probe
design should treat state-transition legality — not per-packet field validity —
as the primary detection surface, and use the NGAP/NAS/SBI field lists above
only as the concrete taps that state machine watches.
