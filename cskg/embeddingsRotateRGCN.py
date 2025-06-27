# cskg3_embeddings.py

import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
#cnx
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

# === Chargement des triplets
triplets_df = pd.read_csv("cskg3_triples.tsv", sep="\t", header=None)
triplets_df.columns = ["head", "relation", "tail"]

# === Création des dictionnaires entité/relation → ID
entities = pd.Series(pd.concat([triplets_df["head"], triplets_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))
relations = pd.Series(triplets_df["relation"].unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

# === Indexation des triplets
h_idx = torch.tensor([entity2id[h] for h in triplets_df["head"]])
r_idx = torch.tensor([rel2id[r] for r in triplets_df["relation"]])
t_idx = torch.tensor([entity2id[t] for t in triplets_df["tail"]])

# === Modèle RotatE
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=100):
        super().__init__()
        self.embedding_dim = embedding_dim
        self.ent = nn.Embedding(num_entities, embedding_dim)
        self.rel = nn.Embedding(num_relations, embedding_dim)

    def forward(self, h_idx, r_idx, t_idx):
        pi = 3.141592653589793
        h = self.ent(h_idx)
        r = self.rel(r_idx) * pi
        t = self.ent(t_idx)
        r_complex = torch.stack([torch.cos(r), torch.sin(r)], dim=-1)
        h_complex = torch.stack([h, torch.zeros_like(h)], dim=-1)
        h_r = torch.stack([
            h_complex[..., 0]*r_complex[..., 0] - h_complex[..., 1]*r_complex[..., 1],
            h_complex[..., 0]*r_complex[..., 1] + h_complex[..., 1]*r_complex[..., 0]
        ], dim=-1)
        t_complex = torch.stack([t, torch.zeros_like(t)], dim=-1)
        score = -torch.norm(h_r - t_complex, dim=-1).sum(dim=-1)
        return score

# === Entraînement RotatE
rotate_model = RotatEModel(len(entity2id), len(rel2id), embedding_dim=64)
optimizer = torch.optim.Adam(rotate_model.parameters(), lr=0.01)

for epoch in range(100):
    rotate_model.train()
    optimizer.zero_grad()
    loss = -torch.mean(rotate_model(h_idx, r_idx, t_idx))
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# === Test de prédiction RotatE
triplets_pred = [("host-001", "at_risk_of", "CVE-2024-99999")]
for h, r, t in triplets_pred:
    score = rotate_model(
        torch.tensor([entity2id[h]]),
        torch.tensor([rel2id[r]]),
        torch.tensor([entity2id[t]])
    ).item()
    print(f"🔍 Score({h}, {r}, {t}) = {score:.4f}")

# === Modèle R-GCN
class RGCN(nn.Module):
    def __init__(self, in_feat, hidden_feat, out_feat, num_rels):
        super().__init__()
        self.conv1 = RGCNConv(in_feat, hidden_feat, num_rels)
        self.conv2 = RGCNConv(hidden_feat, out_feat, num_rels)

    def forward(self, data):
        x, edge_index, edge_type = data.x, data.edge_index, data.edge_type
        x = F.relu(self.conv1(x, edge_index, edge_type))
        x = self.conv2(x, edge_index, edge_type)
        return x

# === Préparation données pour R-GCN
x = torch.randn(len(entity2id), 64)
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_df["head"]],
    [entity2id[t] for t in triplets_df["tail"]]
], dtype=torch.long)
edge_type = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long)

data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id))
data.y = torch.randint(0, 2, (len(entity2id),))  # 0 = sain, 1 = vulnérable
train_mask = torch.rand(len(entity2id)) > 0.3

# === Entraînement R-GCN
rgcn = RGCN(in_feat=64, hidden_feat=32, out_feat=2, num_rels=len(rel2id))
optimizer = torch.optim.Adam(rgcn.parameters(), lr=0.01)

for epoch in range(50):
    rgcn.train()
    optimizer.zero_grad()
    out = rgcn(data)
    loss = F.cross_entropy(out[train_mask], data.y[train_mask])
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        acc = (out.argmax(dim=1) == data.y).float().mean().item()
        print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f} - Acc: {acc:.2%}")
