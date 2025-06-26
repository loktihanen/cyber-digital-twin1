# ======================== 📦 IMPORTS ========================
import streamlit as st
from py2neo import Graph
from PIL import Image
import os
# ======================== ⚙️ CONFIGURATION ========================
st.set_page_config(page_title="Cyber Digital Twin Dashboard", layout="wide")
st.title("🧠 Cyber Digital Twin – Menu principal")

# ======================== 🔐 CONNEXION NEO4J ========================
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

# ======================== 🧭 MENU PRINCIPAL ========================
st.sidebar.title("🗂️ Navigation")

menu_choice = st.sidebar.radio(
    "Accès rapide aux modules :",
    [
        "📌 CSKG1 – NVD (vulnérabilités publiques)",
        "🧩 CSKG2 – Nessus (scans internes)",
        "🔀 CSKG3 – Fusion NVD + Nessus",
        "🔮 Embeddings & RotatE Prediction",
        "📈 R-GCN & Relation Prediction",
        "🧪 Simulation & Digital Twin"
    ]
)

# ======================== 🎯 ROUTAGE DES MODULES ========================
st.markdown("---")

if menu_choice == "📌 CSKG1 – NVD (vulnérabilités publiques)":
    st.header("📌 CSKG1 – Graphe basé sur la NVD")
    st.info("Ce module affiche les vulnérabilités extraites depuis la National Vulnerability Database (CVE, CWE, CPE).")

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
        st.warning("Aucune relation NVD trouvée pour les filtres donnés.")
        st.stop()

    import networkx as nx
    from pyvis.network import Network
    import pandas as pd

    st.subheader("🌐 Visualisation interactive (`pyvis`)")

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

    color_map = {
        "CVE": "#ff4d4d", "CWE": "#ffa500", "CPE": "#6699cc", "Entity": "#dddd00"
    }

    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    path = "/tmp/kg1_nvd.html"
    net.save_graph(path)
    with open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=700, scrolling=True)

    # Statistiques
    st.markdown("### 📊 Statistiques du graphe")
    st.markdown(f"- **Nœuds** : {G.number_of_nodes()}")
    st.markdown(f"- **Arêtes** : {G.number_of_edges()}")
    st.markdown(f"- **Densité** : {nx.density(G):.4f}")
    st.markdown(f"- **Lignes ignorées** : {skipped_rows}")

    # Table
    st.markdown("### 📄 Relations extraites")
    st.dataframe(df, use_container_width=True)


elif menu_choice == "🧩 CSKG2 – Nessus (scans internes)":
    st.header("🧩 CSKG2 – Graphe basé sur les scans Nessus")
    st.info("Ce module permet d'explorer les vulnérabilités détectées dans ton infrastructure via les résultats Nessus (hosts, plugins, CVE).")

    # 🎛️ Filtres
    st.sidebar.subheader("🎛️ Filtres spécifiques à KG2")
    selected_entities = st.sidebar.multiselect(
        "Types d'entités à afficher",
        ["Host", "Plugin", "CVE", "Service", "Port"],
        default=["Host", "Plugin", "CVE"]
    )
    enable_physics = st.sidebar.toggle("Activer l'animation (physique)", value=True)

    # 📥 Chargement des données
    @st.cache_data
    def load_kg2_data():
        query = """
        MATCH (a)-[r]->(b)
        WHERE labels(a)[0] IN ['Host', 'Plugin'] AND labels(b)[0] IN ['Plugin', 'CVE', 'Port', 'Service']
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        """
        return graph_db.run(query).to_data_frame()

    df = load_kg2_data()

    if df.empty:
        st.warning("Aucune relation Nessus trouvée.")
        st.stop()

    import networkx as nx
    from pyvis.network import Network
    import pandas as pd

    st.subheader("🌐 Visualisation interactive (`pyvis`)")

    # 📊 Construction du graphe
    G = nx.DiGraph()
    skipped = 0
    for _, row in df.iterrows():
        src = row.get("source")
        tgt = row.get("target")
        src_type = row.get("source_type")
        tgt_type = row.get("target_type")

        if not src or not tgt or pd.isna(src) or pd.isna(tgt):
            skipped += 1
            continue

        if src_type not in selected_entities and tgt_type not in selected_entities:
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=row["relation"])

    color_map = {
        "Host": "#00cc66", "Plugin": "#66ccff", "CVE": "#ff4d4d",
        "Service": "#ffaa00", "Port": "#9966cc"
    }

    # 🌐 Configuration PyVis
    net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white")

    if enable_physics:
        net.barnes_hut()
    else:
        net.set_options('''var options = { "physics": { "enabled": false } }''')

    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    path = "/tmp/kg2_nessus.html"
    net.save_graph(path)
    with open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=700, scrolling=True)

    # 📈 Statistiques
    st.markdown("### 📊 Statistiques du graphe")
    st.markdown(f"- **Nœuds** : {G.number_of_nodes()}")
    st.markdown(f"- **Arêtes** : {G.number_of_edges()}")
    st.markdown(f"- **Densité** : {nx.density(G):.4f}")
    st.markdown(f"- **Lignes ignorées** : {skipped}")

    # 📄 Table des relations
    st.markdown("### 📄 Relations extraites")
    st.dataframe(df, use_container_width=True)

elif menu_choice == "🔀 CSKG3 – Fusion NVD + Nessus":
    import networkx as nx
    from pyvis.network import Network
    import tempfile
    import os
    import pandas as pd

    st.header("🔀 CSKG3 – Graphe fusionné & enrichi")
    st.info("Visualisation interactive du graphe fusionné (vulnérabilités, plugins, hôtes, OS, ports, applications, etc.)")

    # --- Statistiques générales
    col1, col2, col3 = st.columns(3)
    with col1:
        total_nodes = graph_db.run("MATCH (n) RETURN count(n)").evaluate()
        st.metric("🧠 Nœuds total", total_nodes)
    with col2:
        total_edges = graph_db.run("MATCH ()-[r]->() RETURN count(r)").evaluate()
        st.metric("🔗 Relations total", total_edges)
    with col3:
        total_cve_unified = graph_db.run("MATCH (n:CVE_UNIFIED) RETURN count(n)").evaluate()
        st.metric("🧬 CVE_UNIFIED", total_cve_unified)

    st.markdown("---")

    # === Construction du graphe enrichi limité à 500 nœuds ===
    def build_cskg3_graph():
        query_nodes = """
        MATCH (n)
        WHERE n:CVE_UNIFIED OR n:CVE OR n:Plugin OR n:Host OR n:OS OR n:Port OR n:Service OR n:Software OR n:CPE OR n:CWE OR n:IP OR n:Application
        RETURN id(n) AS id, n.name AS name, labels(n)[0] AS label, n.severity AS severity
        LIMIT 500
        """
        nodes = graph_db.run(query_nodes).data()
        node_ids = [n["id"] for n in nodes]

        query_edges = """
        MATCH (a)-[r]->(b)
        WHERE id(a) IN $ids AND id(b) IN $ids
        RETURN id(a) AS source, id(b) AS target, type(r) AS relation
        """
        edges = graph_db.run(query_edges, parameters={"ids": node_ids}).data()

        G = nx.DiGraph()
        for n in nodes:
            severity = n.get("severity", "unknown") or "unknown"
            G.add_node(n["id"], label=n["name"], type=n["label"], severity=severity)
        for e in edges:
            G.add_edge(e["source"], e["target"], label=e["relation"])
        return G

    def draw_pyvis_graph(G):
        net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white", notebook=False)
        color_map = {
            "CVE_UNIFIED": "#ff4d4d", "CVE": "#ff9999", "CPE": "#6699cc", "CWE": "#ffa500",
            "Plugin": "#66ccff", "Host": "#00cc66", "Service": "#ffaa00", "OS": "#cc00cc",
            "Port": "#9966cc", "Software": "#cc9966", "IP": "#00cccc", "Application": "#aaff00"
        }

        for node_id, data in G.nodes(data=True):
            node_type = data.get("type", "Unknown")
            node_label = data.get("label", str(node_id))
            severity = data.get("severity", "unknown").lower()

            color = color_map.get(node_type, "lightgray")
            if node_type == "CVE_UNIFIED":
                if severity == "critical":
                    color = "red"
                elif severity == "high":
                    color = "orange"
                elif severity == "medium":
                    color = "yellow"
                else:
                    color = "lightblue"

            net.add_node(node_id, label=node_label, color=color,
                         title=f"{node_type} | Sévérité: {severity}")

        for src, tgt, data in G.edges(data=True):
            net.add_edge(src, tgt, title=data.get("label", ""))

        tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmpfile.name)
        return tmpfile.name

    # --- Affichage PyVis
    with st.spinner("Chargement et génération du graphe fusionné..."):
        try:
            G = build_cskg3_graph()
            if len(G.nodes) == 0:
                st.warning("⚠️ Le graphe est vide.")
            else:
                html_path = draw_pyvis_graph(G)
                with open(html_path, 'r', encoding='utf-8') as f:
                    html = f.read()
                st.components.v1.html(html, height=700, scrolling=True)
                os.unlink(html_path)

                # --- Statistiques locales du graphe affiché
                st.markdown("---")
                st.markdown("### 📊 Statistiques du graphe enrichi affiché")
                st.markdown(f"- **Nœuds affichés** : {G.number_of_nodes()}")
                st.markdown(f"- **Relations affichées** : {G.number_of_edges()}")
                st.markdown(f"- **Densité** : {nx.density(G):.6f}")

        except Exception as e:
            st.error("❌ Erreur lors de la génération du graphe.")
            st.exception(e)

    # --- Export RDF fusionné
    st.markdown("---")
    st.subheader("📤 Téléchargement du fichier RDF fusionné")
    rdf_file = "kg_fusionne.ttl"
    if os.path.exists(rdf_file):
        with open(rdf_file, "r", encoding="utf-8") as f:
            rdf_content = f.read()
        st.download_button(
            label="📥 Télécharger RDF (Turtle)",
            data=rdf_content,
            file_name=rdf_file,
            mime="text/turtle"
        )
    else:
        st.warning("⚠️ Le fichier `kg_fusionne.ttl` n'existe pas encore. Exécute le script de fusion backend.")

elif menu_choice == "🔮 Embeddings & RotatE Prediction":
    st.header("🔮 Embeddings & Prédiction avec RotatE")
    st.info("Module pour entraîner RotatE (ou TransE, ComplEx, etc.) et prédire des relations manquantes.")
    st.warning("🔧 À implémenter : chargement des triplets, PyKEEN, prédiction interactive.")

elif menu_choice == "📈 R-GCN & Relation Prediction":
    st.header("📈 Prédictions par GNN – R-GCN")
    st.info("Exploration par Graph Neural Network (R-GCN) pour la complétion et la classification des relations.")
    st.warning("🔧 À implémenter : R-GCN via PyTorch Geometric et visualisation des résultats.")

elif menu_choice == "🧪 Simulation & Digital Twin":
    st.header("🧪 Simulation avec le Jumeau Numérique")
    st.info("Ce module permet de simuler des scénarios cyber via le graphe fusionné.")
    st.warning("🔧 À implémenter : visualisation des impacts, scénarios what-if, propagation.")

# ======================== 🧠 INFOS DE FIN ========================
st.sidebar.markdown("---")
st.sidebar.info("🎓 Projet de M2 – Cyber Digital Twin\nUniversité Lyon 2 – ERIC\nEncadré par l’équipe de recherche KG & Cybersécurité")



