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

# ========== CSKG1 – NVD ==========
if menu == "CSKG1 – NVD":
    from py2neo import Graph
    from pyvis.network import Network
    import pandas as pd
    import tempfile
    import os

    st.title("🧠 CSKG1 – Graphe de connaissances NVD")
    st.info("Visualisation interactive du graphe extrait automatiquement depuis la NVD via l'API officielle et enrichi dans Neo4j.")

    # Connexion à Neo4j
    uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
    user = "neo4j"
    password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
    graph = Graph(uri, auth=(user, password))

    # Récupération des triplets NVD
    query = """
    MATCH (h)-[r]->(t)
    WHERE h.name IS NOT NULL AND t.name IS NOT NULL
    RETURN h.name AS head, type(r) AS relation, t.name AS tail, labels(h)[0] AS head_type, labels(t)[0] AS tail_type
    LIMIT 200
    """
    results = graph.run(query).data()
    df = pd.DataFrame(results)

    if df.empty:
        st.warning("⚠️ Aucun triplet trouvé dans Neo4j. Exécute le pipeline KG1 pour alimenter la base.")
    else:
        st.success(f"✅ {len(df)} triplets extraits de Neo4j pour le graphe NVD.")

        # === Statistiques par type ===
        cve_count = graph.run("MATCH (n:CVE) RETURN count(n) AS count").evaluate()
        cpe_count = graph.run("MATCH (n:CPE) RETURN count(n) AS count").evaluate()
        cwe_count = graph.run("MATCH (n:CWE) RETURN count(n) AS count").evaluate()
        capec_count = graph.run("MATCH (n:CAPEC) RETURN count(n) AS count").evaluate()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🛑 CVE", cve_count)
        col2.metric("🧩 CPE", cpe_count)
        col3.metric("📦 CWE", cwe_count)
        col4.metric("🎯 CAPEC", capec_count)

        # === Statistiques structurelles ===
        num_nodes = len(set(df["head"].tolist() + df["tail"].tolist()))
        num_edges = len(df)
        max_possible_edges = num_nodes * (num_nodes - 1)
        density = round(num_edges / max_possible_edges, 4) if max_possible_edges > 0 else 0.0

        st.subheader("📐 Statistiques structurelles du graphe")
        st.write(f"🔢 Nombre total de nœuds distincts : `{num_nodes}`")
        st.write(f"🔁 Nombre total de relations (arêtes) : `{num_edges}`")
        st.write(f"📊 Densité approximative du graphe : `{density}`")

        # === Visualisation Pyvis ===
        G = Network(height="600px", width="100%", bgcolor="#222222", font_color="white", notebook=False)
        node_colors = {
            "CVE": "red",
            "CPE": "orange",
            "CWE": "green",
            "CAPEC": "purple",
            "Vendor": "blue",
            "Product": "yellow",
            "Version": "lightblue",
            "Entity": "gray"
        }

        added_nodes = set()

        for _, row in df.iterrows():
            h, r, t = row["head"], row["relation"], row["tail"]
            h_type = row["head_type"]
            t_type = row["tail_type"]

            if h not in added_nodes:
                G.add_node(h, label=h, color=node_colors.get(h_type, "white"), title=h_type)
                added_nodes.add(h)
            if t not in added_nodes:
                G.add_node(t, label=t, color=node_colors.get(t_type, "white"), title=t_type)
                added_nodes.add(t)

            G.add_edge(h, t, label=r)

        # Sauvegarde temporaire et affichage
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            G.save_graph(tmp_file.name)
            html_content = open(tmp_file.name, 'r', encoding='utf-8').read()
            st.components.v1.html(html_content, height=600, scrolling=True)

        # Aperçu tabulaire
        with st.expander("🔍 Aperçu des relations (triplets)"):
            st.dataframe(df[["head", "relation", "tail"]])

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
