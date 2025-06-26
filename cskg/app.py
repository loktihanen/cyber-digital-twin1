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

    # === Statistiques de fusion ===
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

    # === Visualisation PyVis uniquement (matplotlib supprimé)
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

    st.subheader("🌐 Visualisation interactive (PyVis)")
    with st.spinner("🔄 Génération du graphe..."):
        html_path = draw_pyvis_graph(G)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        st.components.v1.html(html, height=700, scrolling=True)

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


    
#elif menu_choice == "📈 R-GCN & Relation Prediction":
   # st.header("🧠 R-GCN – Raisonnement sur le graphe de vulnérabilités")
   # st.info("Cette section utilise un modèle R-GCN pour évaluer l'impact et la propagation des vulnérabilités sur l'infrastructure.")

   # import torch
  #  import torch.nn as nn
#    import torch.optim as optim
    #import numpy as np
   # import pandas as pd
  #  import networkx as nx
  #  import matplotlib.pyplot as plt
   # from sklearn.model_selection import train_test_split

   # device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # ======================== 1. EXTRACTION DES TRIPLES ========================
   # query = """
   # MATCH (s:CVE_UNIFIED)-[r]->(o)
   # WHERE s.name IS NOT NULL AND o.name IS NOT NULL
   # RETURN s.name AS head, type(r) AS relation, o.name AS tail
  #  """
  #  data = graph_db.run(query).to_data_frame().dropna()

  #  all_entities = pd.Index(data['head'].tolist() + data['tail'].tolist()).unique()
 #   all_relations = pd.Index(data['relation']).unique()
  #  entity2id = {e: i for i, e in enumerate(all_entities)}
    #relation2id = {r: i for i, r in enumerate(all_relations)}
    #id2entity = {i: e for e, i in entity2id.items()}
   # id2rel = {i: r for r, i in relation2id.items()}

    #triplets = np.array([(entity2id[h], relation2id[r], entity2id[t]) for h, r, t in data.values])
   # train_triples, test_triples = train_test_split(triplets, test_size=0.1, random_state=42)

    # ======================== 2. MODÈLE R-GCN ========================
    #class RGCNLayer(nn.Module):
        #def __init__(self, in_dim, out_dim, num_rels):
           # super().__init__()
            #self.weight = nn.Parameter(torch.Tensor(num_rels, in_dim, out_dim))
            #self.self_loop_weight = nn.Parameter(torch.Tensor(in_dim, out_dim))
            #self.bias = nn.Parameter(torch.Tensor(out_dim))
            #nn.init.xavier_uniform_(self.weight)
            #nn.init.xavier_uniform_(self.self_loop_weight)
           # nn.init.zeros_(self.bias)

        #def forward(self, entity_emb, edge_index, edge_type, num_entities):
           # out = torch.zeros_like(entity_emb)
           # for i in range(edge_index.size(1)):
               # src = edge_index[0, i]
               # dst = edge_index[1, i]
               # rel = edge_type[i]
            #    out[dst] += torch.matmul(entity_emb[src], self.weight[rel])
           # out += torch.matmul(entity_emb, self.self_loop_weight)
            #out += self.bias
          #  return torch.relu(out)

    #class RGCN(nn.Module):
       # def __init__(self, num_entities, num_relations, emb_dim=128, num_layers=2):
            #super().__init__()
           # self.emb_dim = emb_dim
           # self.entity_emb = nn.Embedding(num_entities, emb_dim)
          #  self.layers = nn.ModuleList([
              #  RGCNLayer(emb_dim, emb_dim, num_relations) for _ in range(num_layers)
           # ])
          #  self.score_fn = lambda h, t: -torch.norm(h - t, p=1, dim=1)

     #   def forward(self, edge_index, edge_type):
          #  x = self.entity_emb.weight
            #for layer in self.layers:
               # x = layer(x, edge_index, edge_type, x.size(0))
          #  return x

        #def score(self, entity_emb, head_idx, tail_idx):
           # h = entity_emb[head_idx]
        #    t = entity_emb[tail_idx]
         #   return self.score_fn(h, t)

    # ======================== 3. ENTRAÎNEMENT ========================
    #edge_index = torch.tensor([[h, t] for h, r, t in train_triples], dtype=torch.long).t()
    #edge_type = torch.tensor([r for h, r, t in train_triples], dtype=torch.long)

   # model = RGCN(len(entity2id), len(relation2id)).to(device)
   # optimizer = optim.Adam(model.parameters(), lr=1e-3)
  #  loss_fn = nn.MarginRankingLoss(margin=1.0)

    #EPOCHS = 2
    #for epoch in range(EPOCHS):
       # model.train()
       # optimizer.zero_grad()
      #  entity_emb = model(edge_index.to(device), edge_type.to(device))
        #idx = np.random.choice(len(train_triples), 512)
       # batch = train_triples[idx]
        #heads = torch.tensor(batch[:, 0]).to(device)
       # tails = torch.tensor(batch[:, 2]).to(device)
      #  tails_neg = torch.randint(0, len(entity2id), (len(batch),)).to(device)
        #pos_scores = model.score(entity_emb, heads, tails)
       # neg_scores = model.score(entity_emb, heads, tails_neg)
      #  y = torch.ones_like(pos_scores)
       # loss = loss_fn(pos_scores, neg_scores, y)
       # loss.backward()
      #  optimizer.step()
      #  st.write(f"📉 Epoch {epoch+1}/{EPOCHS} - Loss: {loss.item():.4f}")

    # ======================== 4. ÉVALUATION ========================
    #def evaluate_rgcn(entity_emb, test_triples, k=10):
       # ranks = []
      #  hits = 0
      #  for h, r, t in test_triples:
           # scores = model.score(entity_emb, torch.tensor([h]*len(entity_emb)).to(device), torch.arange(len(entity_emb)).to(device))
          #  _, indices = torch.sort(scores, descending=True)
           # rank = (indices == t).nonzero(as_tuple=False).item() + 1
          #  ranks.append(rank)
          #  if rank <= k:
          #      hits += 1
      #  mrr = np.mean([1.0 / r for r in ranks])
       # st.success(f"📊 Évaluation R-GCN: MRR = {mrr:.4f}, Hits@{k} = {hits/len(test_triples):.4f}")

   # model.eval()
    #entity_emb = model(edge_index.to(device), edge_type.to(device))
    #evaluate_rgcn(entity_emb, test_triples)

    # ======================== 5. SCORING DES HÔTES ========================
    #def compute_host_vuln_scores(hosts, impact_rel_id, entity2id, entity_emb):
      #  scores = {}
        #for host in hosts:
           # if host not in entity2id:
            #    continue
            #host_id = entity2id[host]
           # cves = [e for e in entity2id if "CVE" in e]
           # cve_ids = [entity2id[c] for c in cves]
        #    h_tensor = torch.tensor([host_id]*len(cve_ids)).to(device)
          #  c_tensor = torch.tensor(cve_ids).to(device)
          #  with torch.no_grad():
          #      s = model.score(entity_emb, c_tensor, h_tensor).cpu().numpy().sum()
          #  scores[host] = s
        #return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

   # st.subheader("🔎 Top 10 hôtes vulnérables (R-GCN)")
    #hosts = [e for e in entity2id if "Host" in e or "Windows" in e]
   # impact_rel_id = relation2id.get("IMPACTS", 0)
   # scores = compute_host_vuln_scores(hosts, impact_rel_id, entity2id, entity_emb)
   # df_scores = pd.DataFrame(list(scores.items())[:10], columns=["Host", "Score"])
   # st.dataframe(df_scores)

    # ======================== 6. PROPAGATION VISUELLE ========================
   # def build_graph(triplets, id2e, id2r):
     #   G = nx.DiGraph()
      #  for h, r, t in triplets:
          #  G.add_edge(id2e[h], id2e[t], label=id2r[r])
      #  return G

    #def propagate(G, init_scores, max_steps=3, decay=0.6):
      #  propagated = dict(init_scores)
      #  frontier = list(init_scores.keys())
     #   for _ in range(max_steps):
          #  new_frontier = []
           # for node in frontier:
             #   for neigh in G.successors(node):
               #     score = propagated[node] * decay
              #      if score > propagated.get(neigh, 0):
                #        propagated[neigh] = score
                  #      new_frontier.append(neigh)
         #   frontier = new_frontier
      #  return propagated

  #  G_nx = build_graph(train_triples, id2entity, id2rel)
   # propagated = propagate(G_nx, scores)

 #   top20 = sorted(propagated.items(), key=lambda x: x[1], reverse=True)[:20]
#    st.subheader("📈 Propagation de vulnérabilité")
 #   plt.figure(figsize=(12, 6))
 #   plt.barh([n for n, _ in top20], [s for _, s in top20], color='darkred')
 #   plt.xlabel("Score propagé (R-GCN)")
    #plt.title("Top 20 entités impactées (après propagation)")
   # plt.gca().invert_yaxis()
   # st.pyplot(plt.gcf())

elif menu_choice == "🧪 Simulation & Digital Twin":
    import pandas as pd
    import networkx as nx
    from pyvis.network import Network
    import tempfile

    st.header("🧪 Simulation avec le Jumeau Numérique")
    st.info("Ce module permet de simuler des scénarios cyber à l'aide du graphe fusionné enrichi CVE_UNIFIED et des hôtes réels.")

    # === 1. Extraction des relations Host → Service avec poids (IMPACTS) ===
    @st.cache_data
    def load_simulation_graph():
        query = """
        MATCH (h:Host)-[r:IMPACTS]->(s:Service)
        RETURN h.name AS host, s.name AS service, r.weight AS weight
        """
        return graph_db.run(query).to_data_frame()

    df = load_simulation_graph()

    if df.empty:
        st.warning("Aucune relation IMPACTS détectée. Lance d'abord la fusion et la propagation.")
        st.stop()

    # === 2. Construction du graphe avec NetworkX (et correction des poids) ===
    G = nx.DiGraph()
    for _, row in df.iterrows():
        host = row["host"]
        service = row["service"]
        weight = row.get("weight", 1.0)

        try:
            weight = float(weight)
            label = f"{weight:.2f}"
        except (ValueError, TypeError):
            weight = 1.0
            label = "1.00"

        G.add_node(host, type="Host", label=host, color="#00cc66")
        G.add_node(service, type="Service", label=service, color="#ffaa00")
        G.add_edge(host, service, weight=weight, label=label)

    # === 3. Visualisation interactive PyVis ===
    def draw_pyvis(G):
        net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white", directed=True)
        for node, data in G.nodes(data=True):
            net.add_node(node, label=data["label"], color=data.get("color", "gray"), title=data.get("type", ""))
        for u, v, data in G.edges(data=True):
            net.add_edge(u, v, value=data.get("weight", 1.0), title=data.get("label", ""))
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmp.name)
        return tmp.name

    st.subheader("🌐 Vue interactive : Host → Service")
    with st.spinner("Chargement du graphe..."):
        html_path = draw_pyvis(G)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        st.components.v1.html(html, height=700, scrolling=True)

    # === 4. Simulation What-If ===
    st.subheader("🧪 Simulation What-If")
    host_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "Host"]
    if not host_nodes:
        st.warning("Aucun hôte disponible pour la simulation.")
        st.stop()

    selected_host = st.selectbox("Choisir un hôte à simuler", sorted(host_nodes))
    max_steps = st.slider("Nombre d'étapes de propagation", 1, 5, 2)
    decay = st.slider("Facteur de dissipation", 0.1, 1.0, 0.6)

    def simulate_propagation(G, start_node, decay, max_steps):
        scores = {start_node: 1.0}
        frontier = [start_node]
        for _ in range(max_steps):
            next_frontier = []
            for node in frontier:
                for neighbor in G.successors(node):
                    edge_weight = G[node][neighbor].get('weight', 1.0)
                    propagated_score = scores[node] * decay * edge_weight
                    if propagated_score > scores.get(neighbor, 0):
                        scores[neighbor] = propagated_score
                        next_frontier.append(neighbor)
            frontier = next_frontier
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    if st.button("🚀 Lancer la simulation"):
        results = simulate_propagation(G, selected_host, decay, max_steps)

        st.markdown("### 📊 Résultats de la simulation")
        df_results = pd.DataFrame(list(results.items()), columns=["Noeud", "Score de propagation"])
        st.dataframe(df_results, use_container_width=True)

        st.subheader("🧯 Analyse du risque cumulé")
        total_risk = sum(results.values())
        st.metric("📛 Risque total estimé", f"{total_risk:.2f}")

# ======================== 🧠 INFOS DE FIN ========================
st.sidebar.markdown("---")
st.sidebar.info("🎓 Projet de M2 – Cyber Digital Twin\nUniversité Lyon 2 – ERIC\nEncadré par l’équipe de recherche KG & Cybersécurité")



