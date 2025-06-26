import matplotlib.pyplot as plt
# ======================== 0. IMPORTS ========================
import streamlit as st
from py2neo import Graph
import pandas as pd
import networkx as nx
from pyvis.network import Network
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
# ======================== 2. TITLE ========================
st.set_page_config(page_title="Cyber Digital Twin", layout="wide")
st.title("🛡️ Cyber Digital Twin : Visualisation du Knowledge Graph fusionné")

st.markdown("""
Ce tableau de bord visualise le **Knowledge Graph fusionné** entre les vulnérabilités publiques (NVD/CVE) et les vulnérabilités détectées par **Nessus**.  
Utilise les ontologies **UCO**, **STUCCO** et des techniques de **NER**, **Embeddings** et **Alignement sémantique**.
""")

# ======================== 3. PARAMÈTRES DE RECHERCHE ========================
st.sidebar.header("🔎 Filtres")
max_nodes = st.sidebar.slider("Nombre max de relations", min_value=50, max_value=1000, value=300)
entity_filter = st.sidebar.multiselect("Types d'entité à inclure", options=["CVE", "CWE", "CPE", "Plugin", "Host", "Service", "Port"], default=["CVE", "Host", "Plugin"])
min_cvss = st.sidebar.slider("Score CVSS minimum", 0.0, 10.0, 0.0)

# ======================== 4. QUERY NEO4J ========================
@st.cache_data
def load_data(max_links, min_cvss):
    query = f"""
    MATCH (c:CVE_UNIFIED)-[r]->(x)
    WHERE c.cvss >= {min_cvss}
    RETURN c.name AS source, type(r) AS relation, labels(x)[0] AS target_type, x.name AS target
    LIMIT {max_links}
    """
    return graph.run(query).to_data_frame()

df = load_data(max_nodes, min_cvss)

if df.empty:
    st.warning("Aucune relation trouvée avec les paramètres actuels.")
    st.stop()

# ======================== 5. CONSTRUCTION GRAPHE ========================
@st.cache_data
def build_network(df, allowed_types):
    G = nx.DiGraph()
    for _, row in df.iterrows():
        if row['target_type'] in allowed_types:
            G.add_node(row['source'], type="CVE_UNIFIED")
            G.add_node(row['target'], type=row['target_type'])
            G.add_edge(row['source'], row['target'], label=row['relation'])
    return G

G = build_network(df, entity_filter)

# ======================== 6. VISUALISATION ========================
st.subheader("🕸️ Graphe de connaissances (visualisation interactive)")
net = Network(height="750px", width="100%", bgcolor="#1e1e1e", font_color="white")

color_map = {
    "CVE_UNIFIED": "red", "CWE": "orange", "CPE": "blue",
    "Host": "green", "Plugin": "purple", "Service": "yellow", "Port": "pink"
}

for node, attr in G.nodes(data=True):
    node_type = attr.get("type", "Other")
    color = color_map.get(node_type, "gray")
    net.add_node(node, label=node, color=color)

for src, tgt, edge in G.edges(data=True):
    net.add_edge(src, tgt, label=edge.get("label", ""))

output_path = "/tmp/graph.html"
net.show(output_path)

with open(output_path, 'r', encoding='utf-8') as f:
    html_content = f.read()
    st.components.v1.html(html_content, height=750, scrolling=True)

# ======================== 7. TABLEAUX ========================
st.subheader("📄 Relations extraites")
st.dataframe(df, use_container_width=True)

# ======================== 8. INFOS ========================
st.sidebar.markdown("---")
st.sidebar.info("Projet de M2 • Intégration KG1 (NVD) + KG2 (Nessus) • Alignement + Embeddings + Digital Twin • Visualisation interactive")


