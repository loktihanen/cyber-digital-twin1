# ======================== app.py ========================
import streamlit as st
import pandas as pd
import os
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from py2neo import Graph
import tempfile

# ======================== 1. CONFIGURATION ========================
st.set_page_config(layout="wide")
st.title("🛡️ Cyber Digital Twin – Visualisation en temps réel")

# ======================== 2. CONNEXION NEO4J ========================
@st.cache_resource
def connect_neo4j():
    try:
        uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
        user = "neo4j"
        password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
        graph = Graph(uri, auth=(user, password))
        graph.run("RETURN 1").evaluate()
        st.success("✅ Connexion Neo4j Aura réussie")
        return graph
    except Exception as e:
        st.error(f"❌ Erreur de connexion Neo4j : {e}")
        st.stop()

graph_db = connect_neo4j()

# ======================== 3. REQUÊTE & CONSTRUCTION DU GRAPHE ========================
def build_graph(kg: str, limit=300):
    if kg == "KG1 - NVD":
        query = f"""
        MATCH (a:CVE)-[r]->(b)
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        LIMIT {limit}
        """
    else:
        query = f"""
        MATCH (a:CVE_UNIFIED)-[r]->(b)
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        LIMIT {limit}
        """
    data = graph_db.run(query).data()
    G = nx.DiGraph()
    for row in data:
        src = row["source"]
        tgt = row["target"]
        rel = row["relation"]
        src_type = row.get("source_type", "Other")
        tgt_type = row.get("target_type", "Other")
        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=rel)
    return G

# ======================== 4. VISUALISATION PYVIS ========================
def show_pyvis(G):
    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
    color_map = {
        "CVE": "#ff4d4d", "CVE_UNIFIED": "#ffcc00", "CWE": "#ffa500", "CPE": "#6699cc",
        "Host": "#00cc66", "Plugin": "#66ccff", "Port": "#9966cc", "Service": "#ff9900", "Entity": "#dddd00"
    }
    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, label=data.get("label", ""))

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmp_file.name)
    with open(tmp_file.name, 'r') as f:
        components.html(f.read(), height=700, scrolling=True)

# ======================== 5. VISUALISATION STATIQUE MATPLOTLIB ========================
def show_static_plot(G):
    color_map_mpl = {
        "CVE": "red", "CWE": "orange", "CPE": "blue", "Entity": "green"
    }
    node_colors = [color_map_mpl.get(G.nodes[n].get("type", "Other"), "gray") for n in G.nodes()]
    pos = nx.spring_layout(G, k=0.15, iterations=20, seed=42)

    plt.figure(figsize=(15, 12))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=200, alpha=0.8)
    nx.draw_networkx_edges(G, pos, arrowstyle='-|>', arrowsize=10, alpha=0.5)
    nx.draw_networkx_labels(G, pos, font_size=8, font_color='white')

    patches = [mpatches.Patch(color=c, label=l) for l, c in color_map_mpl.items()]
    patches.append(mpatches.Patch(color='gray', label='Other'))
    plt.legend(handles=patches, loc='best', fontsize=12, title="Types de nœuds")
    plt.title("Visualisation graphe Cybersecurity Knowledge Graph")
    plt.axis('off')
    st.pyplot(plt)

# ======================== 6. INTERFACE STREAMLIT ========================
kg_choice = st.selectbox("Choisir un graphe à afficher :", ["KG1 - NVD", "KG3 - Fusionné"])
G = build_graph(kg_choice)

st.subheader("🌐 Graphe interactif PyVis")
show_pyvis(G)

st.subheader("📊 Graphe statique Matplotlib")
show_static_plot(G)


