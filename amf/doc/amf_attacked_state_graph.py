"""
amf_attacked_state_graph.py — the same 23-state (+6 endpoint) threat-aware
AMF FSM as amf_state_machine.py, with the demo from
amf/doc/fsm_invalid_transition_demo_log.txt overlaid:

  - the legitimate path the UE actually traversed (T0-T4), highlighted green
  - the alerting node where the mismatch was detected (NAS_SECURITY_PENDING),
    circled red
  - the attacker's attempted transition (T5: "replay/abnormal retry", i.e. an
    Authentication Failure message) as a dashed red arrow to a rejection
    marker, since sm_transition_lookup("NAS_SECURITY_PENDING",
    "replay/abnormal retry") returns NULL -- there is no real destination
    node to draw an arrow to
  - for contrast, a grey dotted arrow showing where that same label *does*
    exist in the graph (NAS_AUTHENTICATING -> REPLAY_SUSPECTED), which is
    the state the UE already left -- the point being made visually is that
    the label is real, just not valid from where this UE actually is

Graph/layout/base-drawing code below is copied verbatim from
amf_state_machine.py so the base picture is pixel-for-pixel the same graph;
only the overlay in the "ATTACK OVERLAY" section at the bottom is new.
"""
import matplotlib
matplotlib.use("Agg")  # headless render

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

G = nx.DiGraph()

# Regular
normal = ["REG_RECEIVED","CONTEXT_LOOKUP","IDENTITY_PENDING","AUTH_VECTOR_PENDING",
          "NAS_AUTHENTICATING","NAS_SECURITY_PENDING","UDM_REGISTERING",
          "SUBSCRIPTION_LOADING","POLICY_ASSOCIATING","UE_CONTEXT_READY",
          "SM_CONTEXT_PENDING","INITIAL_CONTEXT_SETUP","REGISTERED_CONNECTED"]
failure = ["REG_REJECTED","AUTH_FAILED","REPLAY_SUSPECTED","SECURITY_FAILED",
           "SECURITY_POLICY_VIOLATION","NF_TIMEOUT","SLICE_REJECTED",
           "PDU_SESSION_REJECTED","CONTEXT_SETUP_FAILED","CLEANUP_REQUIRED"]
endpoints = ["UE/gNB","AMF","AUSF","UDM","PCF","SMF"]

for n in normal: G.add_node(n, kind="normal")
for n in failure: G.add_node(n, kind="failure")
for n in endpoints: G.add_node(n, kind="endpoint")

E = [
("UE/gNB","REG_RECEIVED","InitialUEMessage"),
("REG_RECEIVED","CONTEXT_LOOKUP","valid NAS"),
("REG_RECEIVED","REG_REJECTED","invalid NAS"),
("CONTEXT_LOOKUP","AMF","Namf ContextTransfer"),
("AMF","CONTEXT_LOOKUP","response"),
("CONTEXT_LOOKUP","IDENTITY_PENDING","context unavailable"),
("IDENTITY_PENDING","UE/gNB","Request identity"),
("UE/gNB","IDENTITY_PENDING","Response identity"),
("IDENTITY_PENDING","AUTH_VECTOR_PENDING","identity available"),
("AUTH_VECTOR_PENDING","AUSF","Nausf Authentication"),
("AUSF","AUTH_VECTOR_PENDING","auth vector response"),
("AUTH_VECTOR_PENDING","NAS_AUTHENTICATING","AUSF success"),
("AUTH_VECTOR_PENDING","AUTH_FAILED","AUSF reject"),
("AUTH_VECTOR_PENDING","NF_TIMEOUT","timeout"),
("NAS_AUTHENTICATING","UE/gNB","NAS Authentication"),
("NAS_AUTHENTICATING","NAS_SECURITY_PENDING","RES* valid"),
("NAS_AUTHENTICATING","AUTH_FAILED","RES* invalid"),
("NAS_AUTHENTICATING","REPLAY_SUSPECTED","replay/abnormal retry"),
("NAS_SECURITY_PENDING","UE/gNB","Security Mode Command"),
("UE/gNB","NAS_SECURITY_PENDING","Security Mode Complete"),
("NAS_SECURITY_PENDING","UDM_REGISTERING","integrity success"),
("NAS_SECURITY_PENDING","SECURITY_FAILED","integrity fail"),
("NAS_SECURITY_PENDING","SECURITY_POLICY_VIOLATION","NULL/invalid algorithm"),
("UDM_REGISTERING","UDM","Nudm UECM Registration"),
("UDM","UDM_REGISTERING","registration response"),
("UDM_REGISTERING","SUBSCRIPTION_LOADING","success"),
("UDM_REGISTERING","REG_REJECTED","UDM reject"),
("UDM_REGISTERING","NF_TIMEOUT","timeout"),
("SUBSCRIPTION_LOADING","UDM","Nudm SDM Get"),
("UDM","SUBSCRIPTION_LOADING","subscription data"),
("SUBSCRIPTION_LOADING","POLICY_ASSOCIATING","valid subscription"),
("SUBSCRIPTION_LOADING","SLICE_REJECTED","invalid S-NSSAI"),
("POLICY_ASSOCIATING","PCF","Npcf AM Policy Create"),
("PCF","POLICY_ASSOCIATING","policy response"),
("POLICY_ASSOCIATING","UE_CONTEXT_READY","policy success"),
("POLICY_ASSOCIATING","REG_REJECTED","policy reject"),
("POLICY_ASSOCIATING","NF_TIMEOUT","timeout"),
("UE_CONTEXT_READY","SM_CONTEXT_PENDING","PDU session request"),
("SM_CONTEXT_PENDING","SMF","Nsmf Create/Update SM Context"),
("SMF","SM_CONTEXT_PENDING","SM context response"),
("SM_CONTEXT_PENDING","INITIAL_CONTEXT_SETUP","SMF success"),
("SM_CONTEXT_PENDING","PDU_SESSION_REJECTED","SMF reject"),
("SM_CONTEXT_PENDING","SLICE_REJECTED","slice validation failure"),
("INITIAL_CONTEXT_SETUP","UE/gNB","InitialContextSetupRequest"),
("UE/gNB","INITIAL_CONTEXT_SETUP","setup response"),
("INITIAL_CONTEXT_SETUP","REGISTERED_CONNECTED","setup success"),
("INITIAL_CONTEXT_SETUP","CONTEXT_SETUP_FAILED","setup failure"),
("AUTH_FAILED","CLEANUP_REQUIRED","release partial context"),
("SECURITY_FAILED","CLEANUP_REQUIRED","release partial context"),
("REG_REJECTED","CLEANUP_REQUIRED","cleanup"),
("PDU_SESSION_REJECTED","UE_CONTEXT_READY","retain UE context"),
("CONTEXT_SETUP_FAILED","CLEANUP_REQUIRED","release resources"),
]
for u,v,l in E: G.add_edge(u,v,label=l)

# layered layout
pos={}
for i,n in enumerate(normal): pos[n]=(i*2.1,0)
fail_x = {
"REG_REJECTED":1.5,"AUTH_FAILED":7.5,"REPLAY_SUSPECTED":9.0,
"SECURITY_FAILED":11.0,"SECURITY_POLICY_VIOLATION":12.5,"NF_TIMEOUT":14.5,
"SLICE_REJECTED":18.0,"PDU_SESSION_REJECTED":21.0,
"CONTEXT_SETUP_FAILED":24.0,"CLEANUP_REQUIRED":14.0}
for n,x in fail_x.items(): pos[n]=(x,-3.0 if n!="CLEANUP_REQUIRED" else -5.0)
pos.update({"UE/gNB":(5,3.2),"AMF":(2.3,3.2),"AUSF":(7.0,3.2),
            "UDM":(14.0,3.2),"PCF":(18.0,3.2),"SMF":(22.0,3.2)})


fig,ax=plt.subplots(figsize=(28,14))
nx.draw_networkx_nodes(G,pos,nodelist=normal,node_shape="s",node_size=2700,
                       edgecolors="black", node_color="lightblue",linewidths=1.2,ax=ax)
nx.draw_networkx_nodes(G,pos,nodelist=failure,node_shape="s",node_size=2500,
                       edgecolors="black", node_color="lightblue",linewidths=1.5,ax=ax)
nx.draw_networkx_nodes(G,pos,nodelist=endpoints,node_shape="o",node_size=2600,
                       edgecolors="black", node_color="lightblue",linewidths=1.5,ax=ax)
labels={n:n.replace("_","\n") for n in G.nodes}
nx.draw_networkx_labels(G,pos,labels,font_size=7,font_weight="bold",ax=ax)

# --- edges & edge labels -------------------------------------------------
NODE_SIZE_FOR_MARGINS = 2600

edge_set = {(u,v) for u,v,_ in E}
forward_edges, backward_edges, single_edges = [], [], []
seen_pairs = set()
for u,v,l in E:
    if (v,u) in edge_set:
        pair = frozenset((u,v))
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            forward_edges.append((u,v))
        else:
            backward_edges.append((u,v))
    else:
        single_edges.append((u,v))

edge_label_dict = nx.get_edge_attributes(G,"label")
common_edge_kwargs = dict(arrows=True, arrowstyle="-|>", arrowsize=22, width=1.1,
                          edge_color="black", node_size=NODE_SIZE_FOR_MARGINS,
                          min_source_margin=18, min_target_margin=18, ax=ax)
common_label_kwargs = dict(font_size=8, rotate=True,
                           bbox=dict(fc="white", ec="none", alpha=.85, pad=0.1),
                           node_size=NODE_SIZE_FOR_MARGINS, ax=ax)

if single_edges:
    style = "arc3,rad=0.07"
    nx.draw_networkx_edges(G,pos,edgelist=single_edges,connectionstyle=style,
                           **common_edge_kwargs)
    nx.draw_networkx_edge_labels(G,pos,
        {e:edge_label_dict[e] for e in single_edges},
        connectionstyle=style,label_pos=0.5,**common_label_kwargs)

if forward_edges:
    style = "arc3,rad=0.22"
    nx.draw_networkx_edges(G,pos,edgelist=forward_edges,connectionstyle=style,
                           **common_edge_kwargs)
    nx.draw_networkx_edge_labels(G,pos,
        {e:edge_label_dict[e] for e in forward_edges},
        connectionstyle=style,label_pos=0.32,**common_label_kwargs)

if backward_edges:
    style = "arc3,rad=-0.40"
    nx.draw_networkx_edges(G,pos,edgelist=backward_edges,connectionstyle=style,
                           **common_edge_kwargs)
    nx.draw_networkx_edge_labels(G,pos,
        {e:edge_label_dict[e] for e in backward_edges},
        connectionstyle=style,label_pos=0.32,**common_label_kwargs)

ax.add_patch(FancyBboxPatch((-1,-1),27,2,boxstyle="round,pad=.05",
                            fill=False,linestyle="--",linewidth=2))

# ═══════════════════════════════════════════════════════════════════════
# ATTACK OVERLAY — everything below is new, not in amf_state_machine.py.
# Mirrors amf/doc/fsm_invalid_transition_demo_log.txt (ue=5533).
# ═══════════════════════════════════════════════════════════════════════

# 1. The legitimate path the UE actually traversed, T0-T4 (all real edges,
#    highlighted in green over the black base edges drawn above).
demo_path_edges = [
    ("UE/gNB","REG_RECEIVED"),
    ("REG_RECEIVED","CONTEXT_LOOKUP"),
    ("CONTEXT_LOOKUP","IDENTITY_PENDING"),
    ("IDENTITY_PENDING","AUTH_VECTOR_PENDING"),
    ("AUTH_VECTOR_PENDING","NAS_AUTHENTICATING"),
    ("NAS_AUTHENTICATING","NAS_SECURITY_PENDING"),
]
demo_path_curves = {
    ("UE/gNB","REG_RECEIVED"): "arc3,rad=0.07",
    ("REG_RECEIVED","CONTEXT_LOOKUP"): "arc3,rad=0.07",
    ("CONTEXT_LOOKUP","IDENTITY_PENDING"): "arc3,rad=0.07",
    ("IDENTITY_PENDING","AUTH_VECTOR_PENDING"): "arc3,rad=0.07",
    ("AUTH_VECTOR_PENDING","NAS_AUTHENTICATING"): "arc3,rad=0.22",
    ("NAS_AUTHENTICATING","NAS_SECURITY_PENDING"): "arc3,rad=0.07",
}
for e in demo_path_edges:
    nx.draw_networkx_edges(G, pos, edgelist=[e], connectionstyle=demo_path_curves[e],
                            arrows=True, arrowstyle="-|>", arrowsize=26, width=4.2,
                            edge_color="#1a8a1a", node_size=NODE_SIZE_FOR_MARGINS,
                            min_source_margin=18, min_target_margin=18, ax=ax)

# 2. The alerting node: NAS_SECURITY_PENDING, where the mismatch fired
#    (from_state at T5). Circled in red, offset outward so it doesn't
#    obscure the label.
ax.scatter(*pos["NAS_SECURITY_PENDING"], s=6800, facecolors="none",
           edgecolors="red", linewidths=4.5, zorder=5)
ax.annotate("ALERT: FSM mismatch\ndetected here (T5)",
            xy=pos["NAS_SECURITY_PENDING"],
            xytext=(pos["NAS_SECURITY_PENDING"][0], pos["NAS_SECURITY_PENDING"][1]+1.6),
            ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="red",
            bbox=dict(fc="white", ec="red", pad=3))

# 3. The attacker's attempted transition: NAS_SECURITY_PENDING +
#    "replay/abnormal retry" (an Authentication Failure message) has NO
#    matching edge -- sm_transition_lookup() returns NULL. There is no real
#    destination node, so draw a dashed red arrow straight down into open
#    space below the failure-node row (x=10.5 clears REPLAY_SUSPECTED@9.0
#    and SECURITY_FAILED@11.0 on either side) to a rejection marker, rather
#    than placing the marker where it would overlap those nodes.
reject_xy = (pos["NAS_SECURITY_PENDING"][0], -5.3)
ax.annotate("",
            xy=reject_xy, xytext=pos["NAS_SECURITY_PENDING"],
            arrowprops=dict(arrowstyle="-|>", color="red", lw=2.8, linestyle=(0,(5,3)),
                             shrinkA=42, shrinkB=2))
ax.text(reject_xy[0], reject_xy[1] - 0.25,
        "✗  T5 ATTACK\n\"replay/abnormal retry\"\n(Authentication Failure)\nNO SUCH EDGE — REJECTED",
        color="red", fontsize=9, fontweight="bold", ha="center", va="top",
        bbox=dict(fc="#fff0f0", ec="red", pad=4), zorder=6)

# 4. For contrast: the same label DOES exist, just from a state this UE
#    already left (NAS_AUTHENTICATING, T2-T4) -- grey dotted, de-emphasized.
ax.annotate("",
            xy=pos["REPLAY_SUSPECTED"], xytext=pos["NAS_AUTHENTICATING"],
            arrowprops=dict(arrowstyle="-|>", color="gray", lw=1.4, linestyle=(0,(1,2)),
                             shrinkA=20, shrinkB=20))
mid = ((pos["NAS_AUTHENTICATING"][0]+pos["REPLAY_SUSPECTED"][0])/2,
       (pos["NAS_AUTHENTICATING"][1]+pos["REPLAY_SUSPECTED"][1])/2 - 0.35)
ax.text(mid[0], mid[1], "same label IS valid here\n(already left this state)",
        color="gray", fontsize=7, style="italic", ha="center", va="top")

ax.set_ylim(-9.5, 5.5)
ax.axis("off")
plt.tight_layout()
png="amf_attacked_state_graph.png"
svg="amf_attacked_state_graph.svg"
plt.savefig(png,dpi=220,bbox_inches="tight")
plt.savefig(svg,bbox_inches="tight")
print(png, svg)
