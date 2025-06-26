import streamlit as st
from py2neo import Graph
import pandas as pd
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os
# ======================== CONFIGURATION STREAMLIT ========================
st.set_page_config(page_title="Cyber Digital Twin", layout="wide")
st.title("🧠 Cyber Digital Twin Viewer (KG1 & KG2)")

# ======================== 2. CONNEXION NEO4J ======================
# Connexion Neo4j Aura Free avec paramètres codés en dur

from py2neo import Graph

uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"

# Initialisation de la connexion au graphe Neo4j Aura
graph = Graph(uri, auth=(user, password))

# Test rapide de connexion (optionnel)
try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# ======================== 2. CONFIG & TITRE ========================
st.set_page_config(page_title="Cyber Digital Twin", layout="wide")
st.title("🛡️ Cyber Digital Twin – Visualisation des KG")

st.markdown("""
Ce tableau de bord permet d'explorer :
- **KG1** : Vulnérabilités NVD (CVE, CWE, CPE)
- **KG2** : Résultats Nessus (Host, Plugin, CVE)
- **KG3** : Graphe fusionné et enrichi (CVE_UNIFIED)

📘 Ontologies : `UCO`, `STUCCO`  
🔎 Techniques : `NER`, `Alignement`, `Embedding`, `Reasoning`
""")

# ======================== 3. CHOIX DU KG ========================
kg_option = st.selectbox("🧠 Choisir le graphe à afficher :", ["KG1 - NVD", "KG2 - Nessus", "KG3 - Fusionné"])

# ======================== 4. PARAMÈTRES ========================
st.sidebar.header("🎛️ Filtres")
max_links = st.sidebar.slider("Nombre max de relations", 50, 1000, 300)
entity_filter = st.sidebar.multiselect(
    "Types d'entité à afficher",
    ["CVE", "CVE_UNIFIED", "CWE", "CPE", "Host", "Plugin", "Port", "Service", "Entity"],
    default=["CVE", "CVE_UNIFIED", "Plugin", "Host"]
)

# ======================== 5. REQUÊTES PAR KG ========================
@st.cache_data
def get_graph_data(kg: str, limit: int):
    if kg == "KG1 - NVD":
        query = f"""
        MATCH (a:CVE)-[r]->(b)
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        LIMIT {limit}
        """
    elif kg == "KG2 - Nessus":
        query = f"""
        MATCH (h:Host)-[r1]->(x)-[r2]->(p:Plugin)-[r3]->(c:CVE)
        RETURN h.name AS source, type(r1) AS relation, x.name AS mid,
               type(r2) AS rel2, p.name AS plugin, type(r3) AS rel3, c.name AS target,
               'Host' AS source_type, 'CVE' AS target_type
        LIMIT {limit}
        """
    else:  # KG3
        query = f"""
        MATCH (a:CVE_UNIFIED)-[r]->(b)
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        LIMIT {limit}
        """
    return graph.run(query).data()

data = get_graph_data(kg_option, max_links)

# ======================== 6. CONSTRUCTION DU GRAPHE ========================
G = nx.DiGraph()
color_map = {
    "CVE": "#ff4d4d", "CVE_UNIFIED": "#ffcc00", "CWE": "#ffa500", "CPE": "#6699cc",
    "Host": "#00cc66", "Plugin": "#66ccff", "Port": "#9966cc", "Service": "#ff9900", "Entity": "#dddd00"
}
skipped = 0
for row in data:
    try:
        src = row["source"]
        tgt = row["target"]
        src_type = row.get("source_type", "Other")
        tgt_type = row.get("target_type", "Other")
        rel = row["relation"]
        if src_type not in entity_filter or tgt_type not in entity_filter:
            continue
        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=rel)
    except:
        skipped += 1

# ======================== 7. PYVIS INTERACTIVE ========================
st.subheader("🌐 Visualisation interactive (`pyvis`)")
net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")

for node, data in G.nodes(data=True):
    net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))

for src, tgt, data in G.edges(data=True):
    net.add_edge(src, tgt, title=data.get("label", ""))

path = "/tmp/graph.html"
net.show(path)
with open(path, 'r', encoding='utf-8') as f:
    html = f.read()
    st.components.v1.html(html, height=700, scrolling=True)

# ======================== 8. VISUALISATION MATPLOTLIB ========================
st.subheader("📊 Visualisation statique (`matplotlib`)")
node_colors = [color_map.get(G.nodes[n]["type"], "#cccccc") for n in G.nodes()]
pos = nx.spring_layout(G, k=0.25, seed=42)

plt.figure(figsize=(16, 12))
nx.draw_networkx_nodes(G, pos, node_size=600, node_color=node_colors)
nx.draw_networkx_edges(G, pos, edge_color="gray", arrows=True)
nx.draw_networkx_labels(G, pos, font_size=8)

edge_labels = nx.get_edge_attributes(G, 'label')
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

patches = [mpatches.Patch(color=color, label=label) for label, color in color_map.items()]
plt.legend(handles=patches, loc="upper left", title="Types de nœuds")
plt.title(f"Graphe {kg_option}")
plt.axis("off")
st.pyplot(plt)

# ======================== 9. TABLEAUX ========================
st.subheader("📄 Relations extraites")
df = pd.DataFrame(data)
st.dataframe(df, use_container_width=True)

# ======================== 10. STATISTIQUES ========================
st.sidebar.markdown("---")
st.sidebar.markdown(f"✅ Nœuds : {G.number_of_nodes()}")
st.sidebar.markdown(f"✅ Arêtes : {G.number_of_edges()}")
st.sidebar.markdown(f"⚠️ Lignes ignorées : {skipped}")
st.sidebar.markdown(f"📊 Densité : {nx.density(G):.4f}")
st.sidebar.info("Projet de M2 — Cyber Digital Twin avec graphes KG1, KG2, KG3")



