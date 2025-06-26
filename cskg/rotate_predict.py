# ======================== 1. IMPORTS ========================
from py2neo import Graph
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt
import networkx as nx

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


# ======================== 3. EXTRAIRE LES TRIPLETS ========================
query = """
MATCH (s:CVE_UNIFIED)-[r]->(o)
WHERE s.name IS NOT NULL AND o.name IS NOT NULL
RETURN s.name AS head, type(r) AS relation, o.name AS tail
"""
df = graph.run(query).to_data_frame()
df = df.dropna()

entities = pd.Index(df["head"].tolist() + df["tail"].tolist()).unique()
relations = pd.Index(df["relation"]).unique()
entity2id = {e: i for i, e in enumerate(entities)}
relation2id = {r: i for i, r in enumerate(relations)}

triplets = [(entity2id[h], relation2id[r], entity2id[t]) for h, r, t in df.values]
triplets = np.array(triplets)
train_triples = triplets

# ======================== 4. MODELE ROTATE ========================
class RotatE(nn.Module):
    def __init__(self, num_entities, num_relations, emb_dim=200):
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
        return self.gamma - torch.norm(torch.cat([re_diff, im_diff], dim=1), dim=1)

# ======================== 5. TRAINING ========================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = RotatE(len(entity2id), len(relation2id), emb_dim=400).to(device)
optimizer = optim.Adam(model.parameters(), lr=1e-4)
loss_fn = nn.MarginRankingLoss(margin=1.0)

def generate_negative_sample(batch, num_entities):
    neg = batch.clone()
    neg[:, 2] = torch.randint(0, num_entities, (batch.shape[0],))
    return neg

EPOCHS = 5
BATCH_SIZE = 128

for epoch in range(EPOCHS):
    np.random.shuffle(train_triples)
    total_loss = 0
    for i in range(0, len(train_triples), BATCH_SIZE):
        batch = torch.tensor(train_triples[i:i+BATCH_SIZE], dtype=torch.long).to(device)
        neg = generate_negative_sample(batch, len(entity2id)).to(device)

        pos_scores = model(batch[:,0], batch[:,1], batch[:,2])
        neg_scores = model(neg[:,0], neg[:,1], neg[:,2])
        y = torch.ones(pos_scores.size()).to(device)

        loss = loss_fn(pos_scores, neg_scores, y)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    print(f"🧠 Epoch {epoch+1}/{EPOCHS} - Loss: {total_loss:.4f}")

# ======================== 6. PREDICTION D'IMPACTS ========================
model.eval()
entity_emb = model.entity_emb.weight.data.cpu()
id2entity = {v: k for k, v in entity2id.items()}

def simulate_propagation(cve_name, G, max_steps=2, decay=0.5):
    if cve_name not in entity2id: return {}
    cve_id = entity2id[cve_name]
    scores = {}
    for host, eid in entity2id.items():
        if "Host" in host or "ubuntu" in host or "Windows" in host:
            hid = torch.tensor([eid])
            cid = torch.tensor([cve_id])
            score = model(torch.tensor([cve_id]), torch.tensor([0]), hid)
            if score.item() > 0:
                scores[host] = score.item()

    # Propagation dans G
    propagated = dict(scores)
    frontier = list(scores.keys())
    for _ in range(max_steps):
        new_frontier = []
        for node in frontier:
            for neighbor in G.successors(node):
                new_score = propagated[node] * decay
                if new_score > propagated.get(neighbor, 0):
                    propagated[neighbor] = new_score
                    new_frontier.append(neighbor)
        frontier = new_frontier
    return propagated

# Graphe de propagation
G = nx.DiGraph()
for h, r, t in triplets:
    G.add_edge(id2entity[h], id2entity[t], relation=r)

# ======================== 7. SIMULATION ========================
print("\n🎯 Simulation depuis une CVE critique...")
cve_name = "CVE-2021-34527"
results = simulate_propagation(cve_name, G)

top = sorted(results.items(), key=lambda x: x[1], reverse=True)[:10]
print(f"🔥 Top entités impactées depuis {cve_name} :")
for e, s in top:
    print(f"{e}: {s:.2f}")

# ======================== 8. PLOT ========================
labels, values = zip(*top)
plt.figure(figsize=(10,6))
plt.barh(labels, values, color='darkred')
plt.xlabel("Score de vulnérabilité propagée")
plt.title(f"Propagation à partir de {cve_name}")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig("rotate_prediction.png")
