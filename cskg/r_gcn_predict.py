# ======================== 1. IMPORTS ========================
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
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

# Charger vos triplets depuis fichiers / base
from utils.load_triples import load_data

# ======================== 2. RGCN MODEL ========================
class RGCNLayer(nn.Module):
    def __init__(self, in_dim, out_dim, num_rels):
        super().__init__()
        self.weight = nn.Parameter(torch.Tensor(num_rels, in_dim, out_dim))
        self.self_loop_weight = nn.Parameter(torch.Tensor(in_dim, out_dim))
        self.bias = nn.Parameter(torch.Tensor(out_dim))
        nn.init.xavier_uniform_(self.weight)
        nn.init.xavier_uniform_(self.self_loop_weight)
        nn.init.zeros_(self.bias)

    def forward(self, x, edge_index, edge_type, num_entities):
        out = torch.zeros_like(x)
        for i in range(edge_index.size(1)):
            src = edge_index[0, i]
            dst = edge_index[1, i]
            rel = edge_type[i]
            out[dst] += torch.matmul(x[src], self.weight[rel])
        out += torch.matmul(x, self.self_loop_weight)
        return torch.relu(out + self.bias)

class RGCN(nn.Module):
    def __init__(self, num_entities, num_relations, emb_dim=100, num_layers=2):
        super().__init__()
        self.entity_emb = nn.Embedding(num_entities, emb_dim)
        self.layers = nn.ModuleList([
            RGCNLayer(emb_dim, emb_dim, num_relations) for _ in range(num_layers)
        ])
        self.score_fn = lambda h, t: -torch.norm(h - t, p=1, dim=1)

    def forward(self, edge_index, edge_type):
        x = self.entity_emb.weight
        for layer in self.layers:
            x = layer(x, edge_index, edge_type, self.entity_emb.num_embeddings)
        return x

    def score(self, entity_emb, head_idx, tail_idx):
        h = entity_emb[head_idx]
        t = entity_emb[tail_idx]
        return self.score_fn(h, t)

# ======================== 3. DATA & TRAINING ========================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
train_triples, test_triples, entity2id, relation2id = load_data("data/triples.csv")

edge_index = torch.tensor([[h, t] for h, r, t in train_triples], dtype=torch.long).t()
edge_type = torch.tensor([r for h, r, t in train_triples], dtype=torch.long)

model = RGCN(len(entity2id), len(relation2id), emb_dim=128).to(device)
optimizer = optim.Adam(model.parameters(), lr=1e-3)
loss_fn = nn.MarginRankingLoss(margin=1.0)

print("🔁 Entraînement R-GCN...")
for epoch in range(5):
    model.train()
    optimizer.zero_grad()
    entity_emb = model(edge_index.to(device), edge_type.to(device))

    idx = np.random.choice(len(train_triples), 256)
    batch = train_triples[idx]
    heads = torch.tensor(batch[:, 0]).to(device)
    tails = torch.tensor(batch[:, 2]).to(device)
    tails_neg = torch.randint(0, len(entity2id), (len(batch),)).to(device)

    pos_scores = model.score(entity_emb, heads, tails)
    neg_scores = model.score(entity_emb, heads, tails_neg)
    y = torch.ones_like(pos_scores)
    loss = loss_fn(pos_scores, neg_scores, y)

    loss.backward()
    optimizer.step()
    print(f"Epoch {epoch+1}/5 - Loss: {loss.item():.4f}")

# ======================== 4. EVALUATION ========================
def evaluate_rgcn(entity_emb, test_triples, k=10):
    ranks, hits = [], 0
    for h, r, t in test_triples:
        scores = model.score(entity_emb, torch.tensor([h]*len(entity_emb)).to(device),
                             torch.arange(len(entity_emb)).to(device))
        _, indices = torch.sort(scores, descending=True)
        rank = (indices == t).nonzero(as_tuple=False).item() + 1
        ranks.append(rank)
        if rank <= k:
            hits += 1
    mrr = np.mean([1.0 / r for r in ranks])
    print(f"✅ R-GCN Evaluation: MRR: {mrr:.4f} | Hits@{k}: {hits/len(test_triples):.4f}")

model.eval()
entity_emb = model(edge_index.to(device), edge_type.to(device))
evaluate_rgcn(entity_emb, test_triples)

# ======================== 5. PROPAGATION ========================
def build_propagation_graph(triplets, id2entity, id2rel):
    G = nx.DiGraph()
    for h, r, t in triplets:
        G.add_edge(id2entity[h], id2entity[t], relation=id2rel[r])
    return G

def propagate_from_hosts(initial_scores, G, max_steps=3, decay=0.6):
    propagated = dict(initial_scores)
    frontier = list(initial_scores.keys())
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

# ======================== 6. SIMULATION ========================
def simulate_cve_propagation(cve_name):
    if cve_name not in entity2id:
        print(f"❌ CVE inconnue : {cve_name}")
        return {}

    cve_id = entity2id[cve_name]
    scores = {}
    for host in entity2id:
        if "Host" in host:
            host_id = entity2id[host]
            score = model.score(entity_emb, torch.tensor([cve_id]).to(device),
                                torch.tensor([host_id]).to(device))
            if score.item() > 0:
                scores[host] = score.item()

    G = build_propagation_graph(train_triples, {v: k for k, v in entity2id.items()}, {v: k for k, v in relation2id.items()})
    return propagate_from_hosts(scores, G)

scenar = simulate_cve_propagation("CVE-2021-34527")
for node, score in sorted(scenar.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"{node}: {score:.2f}")
