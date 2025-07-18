import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship
import numpy as np
from sklearn.metrics import classification_report

# --- Connexion à Neo4j
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# --- Extraction triplets depuis Neo4j
query = """
MATCH (h)-[r]->(t)
WHERE h.name IS NOT NULL AND t.name IS NOT NULL
RETURN h.name AS head, type(r) AS relation, t.name AS tail
"""
results = graph.run(query).data()
triplets_df = pd.DataFrame(results)
if triplets_df.empty:
    raise ValueError("Aucun triplet récupéré depuis Neo4j. Vérifiez votre base.")
print(f"✅ {len(triplets_df)} triplets récupérés depuis Neo4j")

# --- Mapping entités et relations
entities = pd.Series(pd.concat([triplets_df["head"], triplets_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))
relations = pd.Series(triplets_df["relation"].unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

h_idx = torch.tensor([entity2id[h] for h in triplets_df["head"]])
r_idx = torch.tensor([rel2id[r] for r in triplets_df["relation"]])
t_idx = torch.tensor([entity2id[t] for t in triplets_df["tail"]])

# --- Modèle RotatE
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=64):
        super().__init__()
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
    if epoch % 10 == 0 or epoch == 2:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# --- Prédiction avec RotatE (exemple)
triplets_pred = [("host-001", "at_risk_of", "CVE-2024-99999")]
matcher = NodeMatcher(graph)

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

# --- Préparation pour R-GCN
x = torch.randn(len(entity2id), 64)
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_df["head"]],
    [entity2id[t] for t in triplets_df["tail"]]
], dtype=torch.long)
edge_type = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long)

data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id))
data.y = torch.randint(0, 2, (len(entity2id),))  # Dummy labels
train_mask = torch.rand(len(entity2id)) > 0.3

# --- Modèle R-GCN
class RGCN(nn.Module):
    def __init__(self, in_feat, hidden_feat, out_feat, num_rels):
        super().__init__()
        self.conv1 = RGCNConv(in_feat, hidden_feat, num_rels)
        self.conv2 = RGCNConv(hidden_feat, out_feat, num_rels)

    def forward(self, data):
        x, edge_index, edge_type = data.x, data.edge_index, data.edge_type
        x = F.relu(self.conv1(x, edge_index, edge_type))
        return self.conv2(x, edge_index, edge_type)

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
    if epoch % 10 == 0 or epoch == 1:
        acc = (out.argmax(dim=1) == data.y).float().mean().item()
        print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f} - Acc: {acc:.2%}")

def inject_vulnerable_property(entity2id, rgcn_out, threshold=0.5):
    for entity, idx in entity2id.items():
        prob_vuln = torch.softmax(rgcn_out[idx], dim=0)[1].item()
        vulnerable = prob_vuln > threshold
        node = matcher.match(name=entity).first()
        if node:
            node["vulnerable"] = vulnerable
            graph.push(node)
            print(f"🛡️ Noeud {entity} : vulnerable = {vulnerable}")

# --- Évaluation link prediction RotatE
def evaluate_link_prediction(model, triplets, entity2id, rel2id, all_triplets_set, k_values=[1,3,10]):
    model.eval()
    ranks = []
    all_entities = list(entity2id.keys())
    num_entities = len(all_entities)
    with torch.no_grad():
        for h, r, t in triplets:
            if h not in entity2id or r not in rel2id or t not in entity2id:
                continue
            h_id = entity2id[h]
            r_id = rel2id[r]
            t_id = entity2id[t]
            head_idx = torch.tensor([h_id] * num_entities)
            rel_idx = torch.tensor([r_id] * num_entities)
            tail_idx = torch.tensor(list(range(num_entities)))
            scores = model(head_idx, rel_idx, tail_idx)
            filtered_scores = scores.clone()
            for candidate_t_id in range(num_entities):
                if (h, r, all_entities[candidate_t_id]) in all_triplets_set and candidate_t_id != t_id:
                    filtered_scores[candidate_t_id] = -float('inf')
            _, indices = torch.sort(filtered_scores, descending=True)
            rank = (indices == t_id).nonzero(as_tuple=False).item() + 1
            ranks.append(rank)
    ranks = np.array(ranks)
    mr = ranks.mean()
    mrr = (1.0 / ranks).mean()
    hits = {}
    for k in k_values:
        hits[k] = (ranks <= k).mean()
    print(f"Mean Rank (MR): {mr:.4f}")
    print(f"Mean Reciprocal Rank (MRR): {mrr:.4f}")
    for k in k_values:
        print(f"Hits@{k}: {hits[k]:.4%}")
    return {"MR": mr, "MRR": mrr, **{f"Hits@{k}": hits[k] for k in k_values}}

# --- Évaluation classification R-GCN
def evaluate_rgcn_nodes(y_true, y_pred):
    print("=== Rapport de classification R-GCN (Noeuds vulnérables) ===")
    print(classification_report(y_true, y_pred, digits=4))


if __name__ == "__main__":
    print("\n▶️ Injection relations at_risk_of (RotatE)...")
    inject_at_risk_of(triplets_pred, entity2id, rel2id, rotate_model)

    print("\n▶️ Entraînement R-GCN & Injection propriétés vulnerable ...")
    rgcn.eval()
    with torch.no_grad():
        out = rgcn(data)
    inject_vulnerable_property(entity2id, out)

    # Exemple d’évaluation link prediction avec les triplets extraits (à ajuster)
    ground_truth_triplets = list(zip(triplets_df["head"], triplets_df["relation"], triplets_df["tail"]))
    all_known_triplets = set(ground_truth_triplets)  # ici train=val=test

    print("\n▶️ Évaluation link prediction (RotatE)...")
    evaluate_link_prediction(rotate_model, ground_truth_triplets, entity2id, rel2id, all_known_triplets)

    # Exemple évaluation classification noeuds R-GCN
    y_true = data.y.numpy()
    y_pred = out.argmax(dim=1).numpy()
    evaluate_rgcn_nodes(y_true, y_pred)
