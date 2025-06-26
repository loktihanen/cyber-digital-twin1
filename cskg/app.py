# ======================== IMPORTS ========================
import streamlit as st
from py2neo import Graph
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

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


# ======================== QUERIES UTILITAIRES ========================
def get_latest_cves(limit=10):
    query = f"""
    MATCH (c:CVE)
    RETURN c.name AS ID, c.description AS Description, c.published AS Date
    ORDER BY Date DESC
    LIMIT {limit}
    """
    return graph.run(query).to_data_frame()

def get_nessus_relations(limit=50):
    query = f"""
    MATCH (h:Host)-[:EXPOSES]->(p:Port)-[:RUNS_PLUGIN]->(pl:Plugin)-[:DETECTS]->(c:CVE)
    RETURN h.name AS Host, p.number AS Port, pl.name AS Plugin, c.name AS CVE
    LIMIT {limit}
    """
    return graph.run(query).to_data_frame()

def get_knowledge_graph(limit=100):
    query = f"""
    MATCH (a)-[r]->(b)
    RETURN a.name AS source, type(r) AS relation, b.name AS target
    LIMIT {limit}
    """
    results = graph.run(query).data()
    G = nx.DiGraph()
    for row in results:
        G.add_edge(row["source"], row["target"], label=row["relation"])
    return G

# ======================== UI ========================
tab1, tab2, tab3 = st.tabs(["📌 CVEs récentes", "🌐 Graphe interactif", "🔎 Relations Nessus"])

with tab1:
    st.subheader("📌 CVEs récentes (NVD)")
    df_cves = get_latest_cves(limit=20)
    st.dataframe(df_cves, use_container_width=True)

with tab2:
    st.subheader("🌐 Graphe de Connaissances")
    limit = st.slider("Nombre de relations affichées :", 10, 300, 100)
    G = get_knowledge_graph(limit)

    fig, ax = plt.subplots(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.5)
    nx.draw(G, pos, with_labels=True, node_color='skyblue', edge_color='gray',
            node_size=800, font_size=8, ax=ax)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)
    st.pyplot(fig)

with tab3:
    st.subheader("🔎 Relations Host/Plugin/CVE (Nessus)")
    df_nessus = get_nessus_relations()
    st.dataframe(df_nessus, use_container_width=True)

