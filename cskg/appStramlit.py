# app.py
import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from py2neo import Graph

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

st.set_page_config(page_title="CSKG Dashboard", layout="wide")

# ========== SIDEBAR MENU ==========
menu = st.sidebar.radio("📌 Menu", [
    "CSKG1 – NVD",
    "CSKG2 – Nessus",
    "CSKG3 – Fusionné",
    "Simulation",
    "Recommandation",
    "Heatmap"
])

# ========== CSKG1 – NVD =========
if menu == "📌 CSKG1 – NVD (vulnérabilités publiques)":
    import networkx as nx
    from pyvis.network import Network
    import pandas as pd
    import tempfile
    import os

    st.header("📌 CSKG1 – Graphe basé sur la NVD")
    st.info("Ce module affiche les vulnérabilités extraites depuis la National Vulnerability Database (CVE, CWE, CPE).")

    # 🎛️ Filtres dynamiques
    st.sidebar.subheader("🎛️ Filtres spécifiques à KG1")
    min_cvss = st.sidebar.slider("Score CVSS minimum", 0.0, 10.0, 0.0)
    selected_entities = st.sidebar.multiselect("Entités à afficher", ["CVE", "CWE", "CPE", "Entity"], default=["CVE", "CWE", "CPE"])

    @st.cache_data
    def load_kg1_data(min_cvss):
        query = f"""
        MATCH (c:CVE)-[r]->(x)
        WHERE c.cvss_score >= {min_cvss}
        RETURN c.name AS source, type(r) AS relation, x.name AS target, labels(x)[0] AS target_type
        """
        return graph_db.run(query).to_data_frame()

    df = load_kg1_data(min_cvss)

    if df.empty:
        st.warning("⚠️ Aucune relation NVD trouvée pour les filtres donnés.")
        st.stop()

    # Filtres supplémentaires
    relations_list = df["relation"].unique().tolist()
    selected_relations = st.sidebar.multiselect("Relations à afficher", relations_list, default=relations_list)
    df = df[df["relation"].isin(selected_relations)]

    # 🌐 Construction du graphe
    G = nx.DiGraph()
    skipped_rows = 0

    for _, row in df.iterrows():
        src = row.get("source")
        tgt = row.get("target")
        tgt_type = row.get("target_type")

        if not src or not tgt or pd.isna(src) or pd.isna(tgt):
            skipped_rows += 1
            continue
        if tgt_type not in selected_entities:
            continue

        G.add_node(src, type="CVE", label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=row["relation"])

    # 🎨 Pyvis pour visualisation interactive
    st.subheader("🌐 Visualisation interactive (`pyvis`)")
    color_map = {
        "CVE": "#ff4d4d", "CWE": "#ffa500", "CPE": "#6699cc", "Entity": "#dddd00"
    }

    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        html = open(tmp_file.name, 'r', encoding='utf-8').read()
        st.components.v1.html(html, height=700, scrolling=True)

    # 📊 Statistiques
    st.markdown("### 📊 Statistiques du graphe")
    st.markdown(f"- **Nœuds** : {G.number_of_nodes()}")
    st.markdown(f"- **Arêtes** : {G.number_of_edges()}")
    st.markdown(f"- **Densité** : {nx.density(G):.4f}")
    st.markdown(f"- **Lignes ignorées** : {skipped_rows}")

    # 📥 Export GML
    nx.write_gml(G, "/tmp/kg1_filtered.gml")
    with open("/tmp/kg1_filtered.gml", "rb") as f:
        st.download_button("📥 Télécharger le graphe (GML)", f, file_name="kg1_nvd.gml")

    # 📄 Table des relations
    st.markdown("### 📄 Relations extraites")
    st.dataframe(df, use_container_width=True)

# ========== CSKG2 – Nessus ==========
elif menu == "CSKG2 – Nessus":
    st.title("🛡️ CSKG2 – Analyse Nessus")
    st.info("Visualisation des vulnérabilités extraites à partir des résultats de scan Nessus.")
    
    # Exemple de données Nessus simulées
    nessus_df = pd.DataFrame({
        "Host": ["host-01", "host-02"],
        "Vuln": ["CVE-2023-1000", "CVE-2024-8888"],
        "Severity": ["Critical", "High"]
    })
    st.dataframe(nessus_df)

    # Graphe simple
    G = nx.Graph()
    G.add_edges_from([("host-01", "CVE-2023-1000"), ("host-02", "CVE-2024-8888")])
    net = Network(notebook=False, height="400px", width="100%")
    net.from_nx(G)
    net.save_graph("cskg2.html")
    with open("cskg2.html", 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=450)

# ========== CSKG3 – Fusionné ==========
elif menu == "CSKG3 – Fusionné":
    st.title("🔀 CSKG3 – Graphe Fusionné (NVD + Nessus)")
    st.info("Représentation du graphe de connaissances fusionné incluant des relations SAME_AS et enrichissements.")

    # Exemple de graphe fusionné simulé
    G = nx.Graph()
    G.add_edges_from([
        ("host-01", "CVE-2024-1234"),
        ("host-01", "Apache"),
        ("CVE-2024-1234", "Apache"),
        ("CVE-2024-1234", "CVE-2024-9999", {"label": "SAME_AS"})
    ])
    net = Network(notebook=False, height="450px", width="100%")
    net.from_nx(G)
    net.save_graph("cskg3.html")
    with open("cskg3.html", 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=480)

# ========== Simulation ==========
elif menu == "Simulation":
    st.title("🧪 Simulation Cybersécurité (Digital Twin)")
    st.info("Expérimentation d’attaque simulée sur un réseau organisationnel.")
    
    # Exemple de simulation (valeurs fictives)
    hosts = ["host-01", "host-02", "host-03"]
    vuln_status = [True, False, True]
    df = pd.DataFrame({"Host": hosts, "Vulnerable": vuln_status})
    st.dataframe(df)

    # Diagramme de simulation
    fig, ax = plt.subplots()
    colors = ["red" if v else "green" for v in vuln_status]
    ax.bar(hosts, [1]*len(hosts), color=colors)
    ax.set_title("Statut des hôtes")
    st.pyplot(fig)

# ========== Recommandation ==========
elif menu == "Recommandation":
    st.title("🎯 Système de Recommandation")
    st.info("Recommandation d’actions correctives basées sur le graphe.")
    
    # Exemple de recommandation simple
    recs = {
        "host-01": "Mettre à jour Apache vers la version 2.4.58",
        "host-02": "Désactiver SSLv3"
    }
    st.json(recs)

# ========== Heatmap ==========
elif menu == "Heatmap":
    st.title("🔥 Heatmap des Vulnérabilités")
    st.info("Carte de chaleur représentant l’intensité des vulnérabilités par hôte.")

    # Données simulées
    data = np.random.rand(5, 5)
    hosts = [f"host-{i}" for i in range(1, 6)]
    vulns = [f"CVE-{2024+i}-000{i}" for i in range(5)]
    df = pd.DataFrame(data, index=hosts, columns=vulns)

    # Affichage heatmap
    fig, ax = plt.subplots(figsize=(8, 4))
    sns.heatmap(df, annot=True, cmap="Reds", cbar=True)
    st.pyplot(fig)
