# cskg3_embeddings.py

import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship

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



# --- 1. Chargement des triplets
triplets_df = pd.read_csv("cskg/cskg3_triples.tsv", sep="\t", header=None)
triplets_df.columns = ["head", "relation", "tail"]

entities = pd.Series(pd.concat([triplets_df["head"], triplets_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))
relations = pd.Series(triplets_df["relation"].unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

h_idx = torch.tensor([entity2id[h] for h in triplets_df["head"]])
r_idx = torch.tensor([rel2id[r] for r in triplets_df["relation"]])
t_idx = torch.tensor([entity2id[t] for t in triplets_df["tail"]])

# --- 2. Modèle RotatE
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=64):
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

rotate_model = RotatEModel(len(entity2id), len(rel2id), embedding_dim=64)
optimizer_rotate = torch.optim.Adam(rotate_model.parameters(), lr=0.01)

print("🛠️ Entraînement RotatE...")
for epoch in range(3):
    rotate_model.train()
    optimizer_rotate.zero_grad()
    loss = -torch.mean(rotate_model(h_idx, r_idx, t_idx))
    loss.backward()
    optimizer_rotate.step()
    if epoch % 10 == 0:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# Triplets candidats à prédire (exemple)
triplets_pred = [("host-001", "at_risk_of", "CVE-2024-99999")]

# --- 3. Connexion Neo4j
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

# Fonction injection relations at_risk_of dans Neo4j
def inject_at_risk_of(predictions, entity2id, rel2id, model, threshold=0.0):
    rel_name = "at_risk_of"
    for h, r, t in predictions:
        if h not in entity2id or r not in rel2id or t not in entity2id:
            print(f"⚠️ Entité ou relation inconnue : {h}, {r}, {t}")
            continue
        score = model(
            torch.tensor([entity2id[h]]),
            torch.tensor([rel2id[r]]),
            torch.tensor([entity2id[t]])
        ).item()
        print(f"Score({h}, {r}, {t}) = {score:.4f}")
        if score > threshold:
            node_h = matcher.match(name=h).first()
            node_t = matcher.match(name=t).first()
            if node_h and node_t:
                rel = Relationship(node_h, rel_name, node_t)
                graph.merge(rel)
                print(f"✅ Relation ({h})-[:{rel_name}]->({t}) injectée (score {score:.4f})")
            else:
                print(f"⚠️ Noeuds Neo4j introuvables : {h} ou {t}")

# --- 4. Préparation données pour R-GCN
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv

x = torch.randn(len(entity2id), 64)  # embeddings initiaux
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_df["head"]],
    [entity2id[t] for t in triplets_df["tail"]]
], dtype=torch.long)
edge_type = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long)

data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id))
data.y = torch.randint(0, 2, (len(entity2id),))  # labels dummy 0/1 vulnérable/sain
train_mask = torch.rand(len(entity2id)) > 0.3

# --- 5. Modèle R-GCN
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

rgcn = RGCN(in_feat=64, hidden_feat=32, out_feat=2, num_rels=len(rel2id))
optimizer_rgcn = torch.optim.Adam(rgcn.parameters(), lr=0.01)

print("\n🛠️ Entraînement R-GCN...")
for epoch in range(2):
    rgcn.train()
    optimizer_rgcn.zero_grad()
    out = rgcn(data)
    loss = F.cross_entropy(out[train_mask], data.y[train_mask])
    loss.backward()
    optimizer_rgcn.step()
    if epoch % 10 == 0:
        acc = (out.argmax(dim=1) == data.y).float().mean().item()
        print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f} - Acc: {acc:.2%}")

# --- 6. Injection propriété vulnerable dans Neo4j
def inject_vulnerable_property(entity2id, rgcn_out, threshold=0.5):
    for entity, idx in entity2id.items():
        prob_vuln = torch.softmax(rgcn_out[idx], dim=0)[1].item()
        vulnerable = prob_vuln > threshold
        node = matcher.match(name=entity).first()
        if node:
            node["vulnerable"] = vulnerable
            graph.push(node)
            print(f"🛡️ Noeud {entity} : vulnerable = {vulnerable}")

# --- 7. Pipeline complet
if __name__ == "__main__":
    print("\nInjection relations at_risk_of (RotatE)...")
    inject_at_risk_of(triplets_pred, entity2id, rel2id, rotate_model, threshold=0.0)

    print("\nInjection propriétés vulnerable (R-GCN)...")
    rgcn.eval()
    with torch.no_grad():
        out = rgcn(data)
    inject_vulnerable_property(entity2id, out, threshold=0.5)

