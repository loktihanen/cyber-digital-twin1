# ======================== app.py ========================
import streamlit as st
import pandas as pd
import os
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

# ======================== 1. TITRE ========================
st.set_page_config(layout="wide")
st.title("🛡️ Cyber Digital Twin – Visualisation & Simulation")

# ======================== 2. MENU ========================
menu = st.sidebar.radio("Accès aux graphes et modules", [
    "📂 CSKG1 (NVD)",
    "🖧 CSKG2 (Nessus)",
    "🔗 CSKG3 Fusionné",
    "📊 Embeddings RotatE",
    "🧠 R-GCN Prediction",
    "🚨 Simulation d'Attaque"
])

# ======================== 3. CHARGER HTML PYVIS ========================
def show_graph_html(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
            components.html(html, height=800, scrolling=True)
    else:
        st.warning("Fichier HTML introuvable : " + path)

# ======================== 4. AFFICHAGE PAR SECTION ========================
if menu == "📂 CSKG1 (NVD)":
    st.header("📂 Graphe NVD (CSKG1)")
    show_graph_html("data/visuals/cskg1_nvd.html")

elif menu == "🖧 CSKG2 (Nessus)":
    st.header("🖧 Graphe Nessus (CSKG2)")
    show_graph_html("data/visuals/cskg2_nessus.html")

elif menu == "🔗 CSKG3 Fusionné":
    st.header("🔗 Graphe Fusionné (CSKG3)")
    show_graph_html("data/visuals/graph.html")

elif menu == "📊 Embeddings RotatE":
    st.header("📊 Visualisation des embeddings RotatE")
    if os.path.exists("data/embeddings/rotate_tsne.csv"):
        df = pd.read_csv("data/embeddings/rotate_tsne.csv")
        st.dataframe(df.head())
        st.pyplot(
            lambda: __import__('matplotlib.pyplot').scatter(df['x'], df['y'], c=df['cluster'], cmap="tab10"))
        st.image("data/embeddings/rotate_tsne.png")
    else:
        st.warning("Embeddings non trouvés.")

elif menu == "🧠 R-GCN Prediction":
    st.header("🧠 R-GCN : Prédiction de propagation")
    if os.path.exists("rotate_prediction.png"):
        st.image("rotate_prediction.png")
    else:
        st.warning("Aucune visualisation de prédiction disponible.")

elif menu == "🚨 Simulation d'Attaque":
    st.header("🚨 Simulation – CVE vers hôtes et services")
    st.markdown("Ce module affiche les entités potentiellement impactées par une CVE.")
    cve_input = st.text_input("Entrer une CVE (ex: CVE-2021-34527):")
    if st.button("Simuler") and cve_input:
        import json
        from rotate_predict import simulate_propagation
        from py2neo import Graph

        @st.cache_resource
        def connect_neo4j():
            uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
            user = "neo4j"
            password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
            return Graph(uri, auth=(user, password))
        graph = connect_neo4j()
        g = Graph(uri, auth=(user, password))
        results = simulate_propagation(cve_input, nx.DiGraph())

        if results:
            st.write(f"Top 10 entités impactées par {cve_input}")
            for ent, score in sorted(results.items(), key=lambda x: x[1], reverse=True)[:10]:
                st.write(f"{ent} → Score: {score:.2f}")
        else:
            st.warning("Aucune propagation trouvée pour cette CVE.")



