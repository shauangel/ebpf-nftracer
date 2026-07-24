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


fig,ax=plt.subplots(figsize=(28,12))
nx.draw_networkx_nodes(G,pos,nodelist=normal,node_shape="s",node_size=2700,
                       edgecolors="black", node_color="lightblue",linewidths=1.2,ax=ax)
nx.draw_networkx_nodes(G,pos,nodelist=failure,node_shape="s",node_size=2500,
                       edgecolors="black", node_color="lightblue",linewidths=1.5,ax=ax)
nx.draw_networkx_nodes(G,pos,nodelist=endpoints,node_shape="o",node_size=2600,
                       edgecolors="black", node_color="lightblue",linewidths=1.5,ax=ax)
labels={n:n.replace("_","\n") for n in G.nodes}
nx.draw_networkx_labels(G,pos,labels,font_size=7,font_weight="bold",ax=ax)

# --- edges & edge labels -------------------------------------------------
# A uniform node_size estimate is passed to draw_networkx_edges so that the
# arrow shrink/margin math matches the actually-drawn node sizes (2500-2700).
# Without this, networkx assumes the default node_size=300, so the arrow tip
# is calculated to stop well short of the real (much larger) node boundary
# and ends up buried under the node label instead of visible next to it.
NODE_SIZE_FOR_MARGINS = 2600

edge_set = {(u,v) for u,v,_ in E}
# split edges into "forward" / "reciprocal-backward" groups so that any pair
# of nodes with edges in BOTH directions gets two oppositely-curved arcs
# (instead of two arrows drawn on top of each other, which is what caused
# both the invisible-arrow look and the overlapping edge-label text).
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

# single (one-directional) edges: mild curve, label centered
if single_edges:
    style = "arc3,rad=0.07"
    nx.draw_networkx_edges(G,pos,edgelist=single_edges,connectionstyle=style,
                           **common_edge_kwargs)
    nx.draw_networkx_edge_labels(G,pos,
        {e:edge_label_dict[e] for e in single_edges},
        connectionstyle=style,label_pos=0.5,**common_label_kwargs)

# reciprocal pairs: bow the two directions apart (+rad / -rad) and slide
# their labels toward opposite ends of the edge so they don't collide
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
ax.axis("off")
plt.tight_layout()
png="amf_threat_aware_state_graph.png"
svg="amf_threat_aware_state_graph.svg"
plt.savefig(png,dpi=220,bbox_inches="tight")
plt.savefig(svg,bbox_inches="tight")
plt.show()
print(png, svg)
