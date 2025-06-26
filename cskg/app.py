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
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    st.header("🔀 CSKG3 – Graphe fusionné & enrichi")
    st.info("Visualisation du graphe résultant de la fusion entre les CVE NVD et Nessus (via SAME_AS → CVE_UNIFIED)")

    # === Requête pour le graphe principal ===
    query = """
    MATCH (a)-[r]->(b)
    WHERE a:CVE OR a:CVE_UNIFIED OR a:Plugin OR a:Host OR a:Service
    RETURN a.name AS source, type(r) AS relation, b.name AS target,
           labels(a)[0] AS source_type, labels(b)[0] AS target_type
    LIMIT 300
    """
    data = graph_db.run(query).data()

    # === Construction du graphe NetworkX ===
    G = nx.DiGraph()
    color_map = {
        "CVE": "#ff4d4d",
        "CVE_UNIFIED": "#ffcc00",
        "Plugin": "#66ccff",
        "Host": "#00cc66",
        "Service": "#ffa500"
    }

    skipped = 0
    for row in data:
        src = row.get("source")
        tgt = row.get("target")
        rel = row.get("relation")
        src_type = row.get("source_type")
        tgt_type = row.get("target_type")

        if not src or not tgt:
            skipped += 1
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=rel)

    # === Récupération des statistiques de fusion et alignement ===
    nb_unifies = graph_db.run("""
        MATCH (c:CVE)-[:SAME_AS]-(n:CVE)
        WHERE c.source = 'NVD' AND n.source = 'NESSUS'
        WITH DISTINCT c.name AS cname
        MATCH (u:CVE_UNIFIED {name: cname})
        RETURN count(DISTINCT u) AS nb
    """).evaluate()

    total_fusionnees = graph_db.run("""
        MATCH (c:CVE)-[:SAME_AS]-(n:CVE)
        WHERE c.source = 'NVD' AND n.source = 'NESSUS'
        RETURN count(DISTINCT c) AS total
    """).evaluate()

    same_as_total = graph_db.run("""
        MATCH (:CVE)-[r:SAME_AS]-(:CVE)
        RETURN count(r) AS total
    """).evaluate()

    # === Visualisation PyVis ===
    def draw_pyvis_graph(G):
        net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
        for node, data in G.nodes(data=True):
            node_type = data.get("type", "Unknown")
            color = color_map.get(node_type, "lightgray")
            net.add_node(node, label=data.get("label", node), color=color, title=node_type)
        for src, tgt, data in G.edges(data=True):
            net.add_edge(src, tgt, title=data.get("label", ""))
        tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmpfile.name)
        return tmpfile.name

    # === Affichage PyVis
    st.subheader("🌐 Visualisation interactive (PyVis)")
    with st.spinner("🔄 Génération du graphe..."):
        html_path = draw_pyvis_graph(G)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        st.components.v1.html(html, height=700, scrolling=True)

    # === Visualisation statique matplotlib
    st.subheader("📊 Visualisation statique (matplotlib)")
    node_colors = [color_map.get(G.nodes[n].get("type", "Other"), "#cccccc") for n in G.nodes()]
    pos = nx.spring_layout(G, k=0.3, seed=42)

    plt.figure(figsize=(18, 12))
    nx.draw_networkx_nodes(G, pos, node_size=600, node_color=node_colors)
    nx.draw_networkx_edges(G, pos, edge_color="gray", arrows=True)
    nx.draw_networkx_labels(G, pos, font_size=9)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color="orange", font_size=7)

    legend_patches = [mpatches.Patch(color=c, label=l) for l, c in color_map.items()]
    plt.legend(handles=legend_patches, loc="best", title="Types de nœuds")
    plt.title("🔎 Graphe des vulnérabilités fusionnées (CSKG3)", fontsize=16)
    plt.axis("off")
    st.pyplot(plt)

    # === Statistiques du graphe ===
    st.markdown("### 📈 Statistiques CSKG3")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🧠 Nœuds visibles", G.number_of_nodes())
    with col2:
        st.metric("🔗 Relations visibles", G.number_of_edges())
    with col3:
        st.metric("📊 Densité", f"{nx.density(G):.4f}")

    st.caption(f"⚠️ Lignes ignorées (valeurs nulles) : {skipped}")

    # === Statistiques de fusion ===
    st.markdown("### 🧬 Alignement & Fusion CVE_UNIFIED")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔀 Relations SAME_AS", same_as_total)
    with col2:
        st.metric("✅ CVE fusionnées", total_fusionnees)
    with col3:
        st.metric("🧬 CVE_UNIFIED créées", nb_unifies)

    # === Téléchargement RDF ===
    st.markdown("---")
    st.subheader("📤 RDF exporté (Turtle)")
    rdf_file = "kg_fusionne.ttl"
    if os.path.exists(rdf_file):
        with open(rdf_file, "r", encoding="utf-8") as f:
            rdf_content = f.read()
        st.download_button(
            label="📥 Télécharger RDF (kg_fusionne.ttl)",
            data=rdf_content,
            file_name="kg_fusionne.ttl",
            mime="text/turtle"
        )
    else:
        st.warning("⚠️ Le fichier `kg_fusionne.ttl` est introuvable. Exécute `rdf_export.py` ou `propagate_impacts.py`.")

elif menu_choice == "🔮 Embeddings & RotatE Prediction":
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import numpy as np
    import pandas as pd
    from py2neo import Graph
    from sklearn.model_selection import train_test_split
    import matplotlib.pyplot as plt
    import networkx as nx

    st.header("🔮 Embeddings & Prédiction avec RotatE")
    st.info("Ce module entraîne le modèle RotatE sur les triplets CVE_UNIFIED et prédit des relations ou entités manquantes.")

    # Connexion à Neo4j
    uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
    user = "neo4j"
    password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
    graph = Graph(uri, auth=(user, password))

    # Extraction des triplets
    query = """
    MATCH (s:CVE_UNIFIED)-[r]->(o)
    WHERE s.name IS NOT NULL AND o.name IS NOT NULL
    RETURN s.name AS head, type(r) AS relation, o.name AS tail
    """
    df = graph.run(query).to_data_frame().dropna()
    all_entities = pd.Index(df['head'].tolist() + df['tail'].tolist()).unique()
    all_relations = pd.Index(df['relation']).unique()

    entity2id = {entity: idx for idx, entity in enumerate(all_entities)}
    relation2id = {rel: idx for idx, rel in enumerate(all_relations)}
    triplets = [(entity2id[h], relation2id[r], entity2id[t]) for h, r, t in df.values]
    triplets = np.array(triplets)

    train_triples, test_triples = train_test_split(triplets, test_size=0.1, random_state=42)

    # Modèle RotatE
    class RotatE(nn.Module):
        def __init__(self, num_entities, num_relations, emb_dim=400):
            super().__init__()
            assert emb_dim % 2 == 0
            self.emb_dim = emb_dim
            self.entity_emb = nn.Embedding(num_entities, emb_dim)
            self.relation_emb = nn.Embedding(num_relations, emb_dim // 2)
            self.gamma = nn.Parameter(torch.Tensor([12.0]))
            self.init_weights()

        def init_weights(self):
            nn.init.uniform_(self.entity_emb.weight, -1, 1)
            nn.init.uniform_(self.relation_emb.weight, 0, 2 * np.pi)

        def forward(self, head, rel, tail):
            head_e = self.entity_emb(head)
            tail_e = self.entity_emb(tail)
            rel_phase = self.relation_emb(rel)
            re_head, im_head = torch.chunk(head_e, 2, dim=1)
            re_tail, im_tail = torch.chunk(tail_e, 2, dim=1)
            phase = rel_phase / (2 * np.pi)
            re_rel = torch.cos(phase)
            im_rel = torch.sin(phase)
            re_rot = re_head * re_rel - im_head * im_rel
            im_rot = re_head * im_rel + im_head * re_rel
            re_diff = re_rot - re_tail
            im_diff = im_rot - im_tail
            score = self.gamma - torch.norm(torch.cat([re_diff, im_diff], dim=1), dim=1)
            return score

    # Entraînement
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = RotatE(len(entity2id), len(relation2id)).to(device)
    optimizer = optim.Adam(model.parameters(), lr=1e-4)
    loss_fn = nn.MarginRankingLoss(margin=1.0)

    def generate_negative_sample(batch, num_entities):
        neg = batch.clone()
        neg[:, 2] = torch.randint(0, num_entities, (batch.shape[0],))
        return neg

    EPOCHS = 30
    BATCH_SIZE = 128
    for epoch in range(EPOCHS):
        np.random.shuffle(train_triples)
        total_loss = 0
        for i in range(0, len(train_triples), BATCH_SIZE):
            pos = torch.tensor(train_triples[i:i+BATCH_SIZE], dtype=torch.long).to(device)
            neg = generate_negative_sample(pos.clone(), len(entity2id)).to(device)
            pos_scores = model(pos[:, 0], pos[:, 1], pos[:, 2])
            neg_scores = model(neg[:, 0], neg[:, 1], neg[:, 2])
            y = torch.ones(pos_scores.size()).to(device)
            loss = loss_fn(pos_scores, neg_scores, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        st.text(f"📚 Epoch {epoch+1}/{EPOCHS} - Loss: {total_loss:.4f}")

    # Prédiction d'entités
    def predict_tail(head, relation, top_k=5):
        if head not in entity2id or relation not in relation2id:
            return []
        h = torch.tensor([entity2id[head]]).to(device)
        r = torch.tensor([relation2id[relation]]).to(device)
        tails = torch.arange(len(entity2id)).to(device)
        h_batch = h.repeat(len(tails))
        r_batch = r.repeat(len(tails))
        with torch.no_grad():
            scores = model(h_batch, r_batch, tails)
        top_indices = torch.topk(scores, top_k).indices.cpu().numpy()
        id2entity = {v: k for k, v in entity2id.items()}
        return [id2entity[i] for i in top_indices]

    st.markdown("### 🎯 Exemple de prédiction d'entité")
    example_head = st.selectbox("Tête (CVE ou Host)", list(entity2id.keys()))
    example_relation = st.selectbox("Relation (impacte, utilise...)", list(relation2id.keys()))
    if st.button("Prédire les objets (tails)"):
        result = predict_tail(example_head, example_relation, top_k=5)
        st.write(f"**Top-5 objets pour ({example_head}, {example_relation}, ?)**")
        st.write(result)

    st.success("✅ Module RotatE exécuté avec succès.")

elif menu_choice == "📈 R-GCN & Relation Prediction":
    import streamlit as st
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import numpy as np
    import matplotlib.pyplot as plt

    st.header("📈 Prédictions par GNN – R-GCN")
    st.info("Exploration par Graph Neural Network (R-GCN) pour la complétion et la classification des relations.")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # ======= Définition modèle R-GCN =========
    class RGCNLayer(nn.Module):
        def __init__(self, in_dim, out_dim, num_rels):
            super(RGCNLayer, self).__init__()
            self.weight = nn.Parameter(torch.Tensor(num_rels, in_dim, out_dim))
            self.self_loop_weight = nn.Parameter(torch.Tensor(in_dim, out_dim))
            self.bias = nn.Parameter(torch.Tensor(out_dim))
            nn.init.xavier_uniform_(self.weight)
            nn.init.xavier_uniform_(self.self_loop_weight)
            nn.init.zeros_(self.bias)

        def forward(self, entity_emb, edge_index, edge_type, num_entities):
            out = torch.zeros_like(entity_emb)
            for i in range(edge_index.size(1)):
                src = edge_index[0, i]
                dst = edge_index[1, i]
                rel = edge_type[i]
                out[dst] += torch.matmul(entity_emb[src], self.weight[rel])
            out += torch.matmul(entity_emb, self.self_loop_weight)
            out += self.bias
            return torch.relu(out)

elif menu_choice == "📈 R-GCN & Relation Prediction":
    import streamlit as st
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import numpy as np
    import matplotlib.pyplot as plt

    st.header("📈 Prédictions par GNN – R-GCN")
    st.info("Exploration par Graph Neural Network (R-GCN) pour la complétion et la classification des relations.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # ======= Définition modèle R-GCN =========
    class RGCNLayer(nn.Module):
        def __init__(self, in_dim, out_dim, num_rels):
            super(RGCNLayer, self).__init__()
            self.weight = nn.Parameter(torch.Tensor(num_rels, in_dim, out_dim))
            self.self_loop_weight = nn.Parameter(torch.Tensor(in_dim, out_dim))
            self.bias = nn.Parameter(torch.Tensor(out_dim))
            nn.init.xavier_uniform_(self.weight)
            nn.init.xavier_uniform_(self.self_loop_weight)
            nn.init.zeros_(self.bias)

        def forward(self, entity_emb, edge_index, edge_type, num_entities):
            out = torch.zeros_like(entity_emb)
            for i in range(edge_index.size(1)):
                src = edge_index[0, i]
                dst = edge_index[1, i]
                rel = edge_type[i]
                out[dst] += torch.matmul(entity_emb[src], self.weight[rel])
            out += torch.matmul(entity_emb, self.self_loop_weight)
            out += self.bias
            return torch.relu(out)

    class RGCN(nn.Module):
        def __init__(self, num_entities, num_relations, emb_dim=100, num_layers=2):
            super(RGCN, self).__init__()
            self.emb_dim = emb_dim
            self.num_entities = num_entities
            self.entity_emb = nn.Embedding(num_entities, emb_dim)
            self.layers = nn.ModuleList([
                RGCNLayer(emb_dim, emb_dim, num_relations) for _ in range(num_layers)
            ])
            self.score_fn = lambda h, t: -torch.norm(h - t, p=1, dim=1)

        def forward(self, edge_index, edge_type):
            x = self.entity_emb.weight
            for layer in self.layers:
                x = layer(x, edge_index, edge_type, self.num_entities)
            return x

        def score(self, entity_emb, head_idx, tail_idx):
            h = entity_emb[head_idx]
            t = entity_emb[tail_idx]
            return self.score_fn(h, t)

    # ======= Vérification données dans session_state =======
    required_keys = ['train_triples', 'test_triples', 'entity2id', 'relation2id']
    if not all(k in st.session_state for k in required_keys):
        st.error(f"❌ Les données {', '.join(required_keys)} doivent être chargées au préalable dans st.session_state.")
    else:
        # Conversion en np.array si besoin
        train_triples = np.array(st.session_state.train_triples)
        test_triples = np.array(st.session_state.test_triples)
        entity2id = st.session_state.entity2id
        relation2id = st.session_state.relation2id

        hosts = [e for e in entity2id if e.startswith("Host")]
        impact_rel_id = relation2id.get("IMPACTS", 0)

        edge_index = torch.tensor([[h, t] for h, r, t in train_triples], dtype=torch.long).t().to(device)
        edge_type = torch.tensor([r for h, r, t in train_triples], dtype=torch.long).to(device)

        model = RGCN(len(entity2id), len(relation2id), emb_dim=128).to(device)
        optimizer = optim.Adam(model.parameters(), lr=1e-3)
        loss_fn = nn.MarginRankingLoss(margin=1.0)

        st.write("⚙️ Entraînement du modèle R-GCN...")

        EPOCHS = st.number_input("Nombre d'époques", min_value=1, max_value=50, value=5, step=1)

        losses = []
        with st.spinner("Entraînement en cours..."):
            for epoch in range(EPOCHS):
                model.train()
                optimizer.zero_grad()

                entity_emb = model(edge_index, edge_type)

                batch_size = min(1024, len(train_triples))
                idx = np.random.choice(len(train_triples), batch_size, replace=False)
                batch = train_triples[idx]
                heads = torch.tensor(batch[:, 0]).to(device)
                tails = torch.tensor(batch[:, 2]).to(device)

                tails_neg = torch.randint(0, len(entity2id), (batch_size,), device=device)

                pos_scores = model.score(entity_emb, heads, tails)
                neg_scores = model.score(entity_emb, heads, tails_neg)
                y = torch.ones_like(pos_scores)

                loss = loss_fn(pos_scores, neg_scores, y)
                loss.backward()
                optimizer.step()

                losses.append(loss.item())
                st.write(f"📚 Epoch {epoch+1}/{EPOCHS} - Loss: {loss.item():.4f}")

        # Affichage graphique de la perte
        fig, ax = plt.subplots()
        ax.plot(range(1, EPOCHS+1), losses, marker='o')
        ax.set_xlabel("Epoch")
        ax.set_ylabel("Loss")
        ax.set_title("Courbe de perte durant l'entraînement R-GCN")
        st.pyplot(fig)

        # ====== Évaluation =======
        model.eval()
        entity_emb = model(edge_index, edge_type)

        def evaluate_rgcn(entity_emb, test_triples, k=10):
            ranks = []
            hits = 0
            for h, r, t in test_triples:
                scores = model.score(
                    entity_emb,
                    torch.tensor([h]*len(entity_emb)).to(device),
                    torch.arange(len(entity_emb)).to(device)
                )
                _, indices = torch.sort(scores, descending=True)
                rank = (indices == t).nonzero(as_tuple=False).item() + 1
                ranks.append(rank)
                if rank <= k:
                    hits += 1

            mrr = np.mean([1.0 / r for r in ranks])
            return mrr, hits / len(test_triples)

        mrr, hits_at_10 = evaluate_rgcn(entity_emb, test_triples)
        st.success(f"✅ Évaluation R-GCN : MRR = {mrr:.4f}, Hits@10 = {hits_at_10:.4f}")

        # ===== Scoring des hôtes =====
        def compute_host_vuln_scores_rgcn(hosts, impact_rel_id, entity2id, entity_emb):
            scores = {}
            for host in hosts:
                host_id = entity2id[host]
                cve_entities = [e for e in entity2id if "CVE" in e]
                cve_ids = [entity2id[cve] for cve in cve_entities]

                host_tensor = torch.tensor([host_id] * len(cve_ids)).to(device)
                cve_tensor = torch.tensor(cve_ids).to(device)
                with torch.no_grad():
                    score = model.score(entity_emb, cve_tensor, host_tensor)
                    scores[host] = score.cpu().numpy().sum()
            return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

        host_scores_rgcn = compute_host_vuln_scores_rgcn(hosts, impact_rel_id, entity2id, entity_emb)
        st.write("🏆 Top hôtes vulnérables (R-GCN) :")
        for h, s in list(host_scores_rgcn.items())[:10]:
            st.write(f"- {h}: {s:.2f}")

elif menu_choice == "🧪 Simulation & Digital Twin":
    st.header("🧪 Simulation avec le Jumeau Numérique")
    st.info("Ce module permet de simuler des scénarios cyber via le graphe fusionné.")
    st.warning("🔧 À implémenter : visualisation des impacts, scénarios what-if, propagation.")

# ======================== 🧠 INFOS DE FIN ========================
st.sidebar.markdown("---")
st.sidebar.info("🎓 Projet de M2 – Cyber Digital Twin\nUniversité Lyon 2 – ERIC\nEncadré par l’équipe de recherche KG & Cybersécurité")



