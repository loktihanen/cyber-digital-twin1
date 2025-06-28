import streamlit as st
from py2neo import Graph
from pyvis.network import Network
import tempfile
import os
import pandas as pd
import streamlit.components.v1 as components

# ======= 1. Connexion à Neo4j =======
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

# ======= 2. Interface Streamlit =======
st.set_page_config(page_title="🛡️ Hôtes à Haut Risque", layout="wide")
st.title("🔥 Visualisation des Hôtes à Haut Risque")
st.markdown("Filtrage et exploration des hôtes avec un score de risque élevé dans le graphe CSKG.")

risk_threshold = st.slider("Seuil minimum de riskScore :", min_value=1.0, max_value=10.0, value=7.0, step=0.1)

# ======= 3. Récupération des données depuis Neo4j =======
@st.cache_data(ttl=300)
def get_high_risk_hosts(threshold):
    query = f"""
    MATCH (h:Host)
    WHERE h.riskScore >= {threshold}
    OPTIONAL MATCH (h)-[:vulnerableTo]->(c:CVE_UNIFIED)
    RETURN h.name AS host, h.riskScore AS score, collect(DISTINCT c.name) AS cves
    """
    return graph.run(query).to_data_frame()

df = get_high_risk_hosts(risk_threshold)

if df.empty:
    st.info("✅ Aucun hôte à risque élevé trouvé.")
else:
    st.success(f"🎯 {len(df)} hôtes détectés avec riskScore ≥ {risk_threshold}")

    # Affichage tabulaire
    with st.expander("📋 Voir les données tabulaires"):
        st.dataframe(df)

    # ======= 4. Visualisation interactive avec Pyvis =======
    def draw_graph(df):
        net = Network(height="700px", width="100%", bgcolor="#1a1a1a", font_color="white")
        net.barnes_hut()

        for _, row in df.iterrows():
            host = row["host"]
            risk = round(row["score"], 2)
            cves = row["cves"]

            net.add_node(host, label=f"{host}\nRisk: {risk}", color="red", shape="dot", size=risk * 4)

            for cve in cves:
                if cve:
                    net.add_node(cve, label=cve, color="orange", shape="box", size=10)
                    net.add_edge(host, cve)

        return net

    net = draw_graph(df)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        components.html(open(tmp_file.name, 'r', encoding='utf-8').read(), height=750, scrolling=True)
        os.remove(tmp_file.name)
