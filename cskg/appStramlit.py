

# app.py
import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from py2neo import Graph
import tempfile  # ✅ import requis pour NamedTemporaryFile
import os 
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
if menu == "CSKG1 – NVD":
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
    st.header("🧩 CSKG2 – Graphe basé sur les scans Nessus")
    st.info("Ce module permet d'explorer les vulnérabilités détectées dans ton infrastructure via les résultats Nessus (hosts, plugins, CVE, etc.).")

    # 🎛️ Filtres
    st.sidebar.subheader("🎛️ Filtres spécifiques à KG2")
    selected_entities = st.sidebar.multiselect(
        "Types d'entités à afficher",
        ["Host", "Plugin", "CVE", "Service", "Port", "OperatingSystem", "Scanner", "Severity"],
        default=["Host", "Plugin", "CVE"]
    )
    enable_physics = st.sidebar.toggle("Activer l'animation (physique)", value=True)

    # 📥 Chargement des données
    @st.cache_data
    def load_kg2_data():
        query = """
        MATCH (a)-[r]->(b)
        WHERE labels(a)[0] IN ['Host', 'Plugin', 'Service', 'Port', 'OperatingSystem', 'Scanner', 'Severity']
          AND labels(b)[0] IN ['Plugin', 'CVE', 'Port', 'Service', 'OperatingSystem', 'Scanner', 'Severity']
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        """
        return graph_db.run(query).to_data_frame()

    df = load_kg2_data()

    if df.empty:
        st.warning("Aucune relation Nessus trouvée dans Neo4j.")
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

        # n'affiche que si au moins un des deux nœuds est sélectionné
        if src_type not in selected_entities and tgt_type not in selected_entities:
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=row["relation"])

    # 🎨 Couleurs selon type
    color_map = {
        "Host": "#00cc66",
        "Plugin": "#66ccff",
        "CVE": "#ff4d4d",
        "Service": "#ffaa00",
        "Port": "#9966cc",
        "OperatingSystem": "#cccccc",
        "Scanner": "#00b8d9",
        "Severity": "#ff9900"
    }

    # 🌐 Visualisation PyVis
    net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white")

    if enable_physics:
        net.barnes_hut()
    else:
        net.set_options('''var options = { "physics": { "enabled": false } }''')

    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"), title=data["type"])
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    # 📤 Affichage HTML
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
# ========== CSKG3 – Fusionné ==========
elif menu == "CSKG3 – Fusionné":
    st.header("🔀 CSKG3 – Graphe fusionné & enrichi")
    st.info("Visualisation du graphe résultant de la fusion entre les CVE issues de la NVD et celles issues des scans Nessus, via des relations SAME_AS vers des nœuds CVE_UNIFIED.")

    query = """
    MATCH (a)-[r]->(b)
    WHERE labels(a)[0] IN ['CVE', 'CVE_UNIFIED', 'Plugin', 'Host', 'Service', 'Patch', 'Severity']
      AND labels(b)[0] IN ['CVE', 'CVE_UNIFIED', 'Plugin', 'Host', 'Service', 'Patch', 'Severity']
    RETURN a.name AS source, type(r) AS relation, b.name AS target,
           labels(a)[0] AS source_type, labels(b)[0] AS target_type
    LIMIT 500
    """
    data = graph_db.run(query).data()

    G = nx.DiGraph()
    color_map = {
        "CVE": "#ff4d4d",
        "CVE_UNIFIED": "#ffcc00",
        "Plugin": "#66ccff",
        "Host": "#00cc66",
        "Service": "#ffa500",
        "Patch": "#aa33ff",
        "Severity": "#ff9900"
    }

    skipped = 0
    for row in data:
        src = row.get("source")
        tgt = row.get("target")
        rel = row.get("relation")
        src_type = row.get("source_type")
        tgt_type = row.get("target_type")

        if not src or not tgt or not rel:
            skipped += 1
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=rel)

    nb_unifies = graph_db.run("""
        MATCH (cveu:CVE_UNIFIED)-[:SAME_AS]->(:CVE)
        RETURN count(DISTINCT cveu) AS nb
    """).evaluate()

    total_fusionnees = graph_db.run("""
        MATCH (c:CVE)-[:SAME_AS]-(:CVE)
        RETURN count(DISTINCT c) AS total
    """).evaluate()

    same_as_total = graph_db.run("""
        MATCH (:CVE)-[r:SAME_AS]-(:CVE)
        RETURN count(r) AS total
    """).evaluate()

    def draw_pyvis_graph(G):
        net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
        for node, data in G.nodes(data=True):
            node_type = data.get("type", "gray")
            color = color_map.get(node_type, "gray")
            net.add_node(node, label=data.get("label", node), color=color, title=node_type)
        for src, tgt, data in G.edges(data=True):
            net.add_edge(src, tgt, title=data.get("label", ""))
        tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmpfile.name)
        return tmpfile.name

    st.subheader("🌐 Visualisation interactive (PyVis)")
    with st.spinner("🔄 Génération du graphe..."):
        html_path = draw_pyvis_graph(G)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        st.components.v1.html(html, height=700, scrolling=True)

    st.markdown("### 📈 Statistiques du graphe CSKG3")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🧠 Nœuds visibles", G.number_of_nodes())
    with col2:
        st.metric("🔗 Relations visibles", G.number_of_edges())
    with col3:
        st.metric("📊 Densité", f"{nx.density(G):.4f}")

    st.caption(f"⚠️ Lignes ignorées (valeurs nulles) : {skipped}")

    st.markdown("### 🧬 Alignement & Fusion via CVE_UNIFIED")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔀 Relations SAME_AS", same_as_total)
    with col2:
        st.metric("✅ CVE alignées", total_fusionnees)
    with col3:
        st.metric("🧬 Nœuds CVE_UNIFIED", nb_unifies)


# ========== Simulation ==========
elif menu == "Simulation":

    import streamlit as st
    from py2neo import Graph, NodeMatcher
    import pandas as pd
    import networkx as nx
    from pyvis.network import Network
    import tempfile
    import matplotlib.pyplot as plt
    import seaborn as sns
    from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
    from owlrl import DeductiveClosure, OWLRL_Semantics
    from rdflib.plugins.sparql import prepareQuery

    st.header("🧪 Simulation basée sur le Jumeau Numérique")
    st.info("Ce module regroupe raisonnement OWL, analyse de risques, simulation What-If et visualisation interactive.")

    # ======================== 1. 🔄 Extraction Neo4j ========================
    uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
    user = "neo4j"
    password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
    graph = Graph(uri, auth=(user, password))
    matcher = NodeMatcher(graph)

    query = """
    MATCH (h)-[r:IMPACTS]->(s)
    WHERE h.name IS NOT NULL AND s.name IS NOT NULL
    RETURN h.name AS host, type(r) AS relation, s.name AS service, r.weight AS weight
    """
    df_impacts = graph.run(query).to_data_frame()

    # ======================== 2. 🧠 Raisonnement OWL ========================
    uploaded_file = st.file_uploader("📂 Uploader le fichier OWL enrichi (`cskg3_enriched.ttl`)", type="ttl")
    rdf_graph = RDFGraph()
    CYBER = Namespace("http://example.org/cyber#")
    rdf_graph.bind("cyber", CYBER)

    if uploaded_file:
        try:
            rdf_graph.parse(uploaded_file, format="turtle")
            DeductiveClosure(OWLRL_Semantics).expand(rdf_graph)
            rdf_graph.serialize("cskg3_inferenced.ttl", format="turtle")
            st.success("✅ Raisonnement OWL appliqué avec succès.")
        except Exception as e:
            st.error(f"Erreur lors de l’inférence OWL : {e}")
    else:
        st.warning("Veuillez uploader le fichier `cskg3_enriched.ttl` pour activer le raisonnement OWL.")

    # ======================== 3. 🔍 SPARQL: actifs à risque ========================
    try:
        query_sparql = prepareQuery("""
        PREFIX cyber: <http://example.org/cyber#>
        SELECT ?asset ?cve WHERE {
          ?asset cyber:at_risk_of ?cve .
        }
        """)
        risks = [(row.asset.split("#")[-1], row.cve.split("#")[-1]) for row in rdf_graph.query(query_sparql)]
        df_risks = pd.DataFrame(risks, columns=["Asset", "CVE"])

        if not df_risks.empty:
            st.subheader("🔍 Actifs à risque détectés par inférence")
            st.dataframe(df_risks, use_container_width=True)
        else:
            st.info("Aucun actif à risque détecté par inférence OWL.")
    except Exception as e:
        st.error(f"Erreur SPARQL ou inférence non disponible : {e}")

    # ======================== 4. 🌐 Vue interactive PyVis ========================
    # ======================== 4. 🌐 Vue interactive PyVis ========================
    st.subheader("🌐 Visualisation interactive Host → Service")
    
    G_nx = nx.DiGraph()
    for _, row in df_impacts.iterrows():
        host = row['host']
        service = row['service']
        weight = row['weight'] if pd.notnull(row['weight']) else 1.0
        try:
            weight = float(weight)
        except:
            weight = 1.0

        G_nx.add_node(host, label=host, color="#1f78b4", title="🖥️ Host", shape="dot", size=25)
        G_nx.add_node(service, label=service, color="#ff7f0e", title="🛠️ Service", shape="triangle", size=15)
        G_nx.add_edge(host, service, weight=weight)

    # Création du réseau PyVis
    net = Network(height="750px", width="100%", bgcolor="#202020", font_color="white", directed=True)
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 2,
        "shadow": true,
        "font": {
          "color": "white",
          "face": "Arial"
        }
      },
      "edges": {
        "color": {
          "color": "#cccccc"
        },
        "smooth": {
          "type": "dynamic"
        },
        "arrows": {
          "to": {
            "enabled": true,
            "scaleFactor": 0.6
          }
        }
      },
      "physics": {
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 120,
          "springConstant": 0.08
        },
        "minVelocity": 0.75
      },
      "interaction": {
        "hover": true,
        "navigationButtons": true,
        "tooltipDelay": 200
      }
    }
    """)

    for node, data in G_nx.nodes(data=True):
        net.add_node(node, label=data.get("label", node), title=data.get("title", ""), color=data.get("color"), shape=data.get("shape", "dot"), size=data.get("size", 20))
    for u, v, data in G_nx.edges(data=True):
        w = data.get("weight", 1.0)
        net.add_edge(u, v, value=w, title=f"💥 Poids : {w:.2f}", color="#AAAAAA")

    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r", encoding="utf-8") as f:
        html = f.read()
    st.components.v1.html(html, height=750, scrolling=False)

    # ======================== 5. 🚀 Simulation What-If ========================
    st.subheader("🚀 Simulation What-If (Propagation de risque)")
    hosts = sorted(set(df_impacts["host"]))
    selected_host = st.selectbox("Choisir un hôte à simuler", hosts)
    decay = st.slider("Facteur de dissipation", 0.1, 1.0, 0.6, step=0.05)
    max_depth = st.slider("Profondeur max", 1, 5, 3)

    def simulate_propagation(G, start_node, decay=0.6, max_depth=3):
        scores = {start_node: 1.0}
        frontier = [start_node]
        for step in range(max_depth):
            next_frontier = []
            for node in frontier:
                for neighbor in G.successors(node):
                    weight = G[node][neighbor].get("weight", 1.0)
                    propagated_score = scores[node] * decay * weight
                    if propagated_score > scores.get(neighbor, 0):
                        scores[neighbor] = propagated_score
                        next_frontier.append(neighbor)
            frontier = next_frontier
            if not frontier:
                break
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    if st.button("🚀 Lancer la simulation"):
        results = simulate_propagation(G_nx, selected_host, decay, max_depth)
        st.success(f"Propagation depuis {selected_host} effectuée avec {len(results)} nœuds affectés.")

        # ======================== 7. 📊 Analyse & heatmap ========================
        st.subheader("📊 Heatmap des services impactés")
        service_scores = {n: s for n, s in results.items() if G_nx.nodes[n].get("type") == "Service"}
        if service_scores:
            df_heat = pd.DataFrame.from_dict(service_scores, orient="index", columns=["Score"])
            st.dataframe(df_heat.style.background_gradient(cmap="Reds"), use_container_width=True)
            plt.figure(figsize=(8, max(1, len(df_heat)*0.5)))
            sns.heatmap(df_heat.sort_values("Score", ascending=False), annot=True, cmap="Reds", fmt=".2f")
            plt.title(f"Propagation depuis {selected_host}")
            st.pyplot(plt.gcf())
            plt.clf()
        else:
            st.info("Aucun service impacté détecté.")

    # ======================== 6. 🔗 Chaîne d'attaque simulée ========================
    st.subheader("🔗 Chaîne d'attaque simulée (fictive)")
    attack_chain = [
        ("host-001", "connected_to", "host-002"),
        ("host-002", "connected_to", "host-003"),
        ("host-003", "at_risk_of", "CVE-2024-99999"),
        ("CVE-2024-99999", "targets", "CriticalAsset-01")
    ]
    G_attack = nx.DiGraph()
    for h, r, t in attack_chain:
        G_attack.add_edge(h, t, label=r)

    pos = nx.spring_layout(G_attack)
    plt.figure(figsize=(8, 4))
    nx.draw(G_attack, pos, with_labels=True, node_color="lightcoral", node_size=2000, font_size=9, edge_color="gray")
    edge_labels = nx.get_edge_attributes(G_attack, 'label')
    nx.draw_networkx_edge_labels(G_attack, pos, edge_labels=edge_labels)
    st.pyplot(plt.gcf())
    plt.clf()

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
