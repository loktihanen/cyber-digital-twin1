# ======================== 1. IMPORTS ========================
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from py2neo import Graph
from sklearn.manifold import TSNE
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import os

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

# ======================== 3. EXTRACTION TRIPLETS ========================
query = """
MATCH (s:CVE_UNIFIED)-[r]->(o)
WHERE s.name IS NOT NULL AND o.name IS NOT NULL
RETURN s.name AS head, type(r) AS relation, o.name AS tail
"""
data = graph.run(query).to_data_frame().dropna()

# ======================== 4. ENCODAGE ========================
entities = pd.Index(data['head'].tolist() + data['tail'].tolist()).unique()
relations = pd.Index(data['relation']).unique()
entity2id = {e: i for i, e in enumerate(entities)}
relation2id = {r: i for i, r in enumerate(relations)}
triplets = np.array([(entity2id[h], relation2id[r], entity2id[t]) for h, r, t in data.values])

train_triples, test_triples = train_test_split(triplets, test_size=0.1, random_state=42)

# ======================== 5. MODELE ROTATE ========================
class RotatE(nn.Module):
    def __init__(self, n_entities, n_relations, emb_dim=200):
        super().__init__()
        self.emb_dim = emb_dim
        self.entity_emb = nn.Embedding(n_entities, emb_dim)
        self.relation_emb = nn.Embedding(n_relations, emb_dim // 2)
        self.gamma = nn.Parameter(torch.Tensor([12.0]))
        self.init_weights()

    def init_weights(self):
        nn.init.uniform_(self.entity_emb.weight, -1, 1)
        nn.init.uniform_(self.relation_emb.weight, 0, 2 * np.pi)

    def forward(self, h, r, t):
        h_e = self.entity_emb(h)
        t_e = self.entity_emb(t)
        phase_r = self.relation_emb(r)

        re_h, im_h = torch.chunk(h_e, 2, dim=1)
        re_t, im_t = torch.chunk(t_e, 2, dim=1)

        phase = phase_r / (2 * np.pi)
        re_r = torch.cos(phase)
        im_r = torch.sin(phase)

        re_rot = re_h * re_r - im_h * im_r
        im_rot = re_h * im_r + im_h * re_r

        re_diff = re_rot - re_t
        im_diff = im_rot - im_t

        score = self.gamma - torch.norm(torch.cat([re_diff, im_diff], dim=1), dim=1)
        return score

# ======================== 6. ENTRAINEMENT ========================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = RotatE(len(entity2id), len(relation2id)).to(device)
optimizer = optim.Adam(model.parameters(), lr=0.01)
epochs = 5

for epoch in range(epochs):
    np.random.shuffle(train_triples)
    total_loss = 0
    model.train()
    for h, r, t in train_triples:
        h_t = torch.tensor([h]).to(device)
        r_t = torch.tensor([r]).to(device)
        t_t = torch.tensor([t]).to(device)

        pos_score = model(h_t, r_t, t_t)

        # Négatif sampling
        t_neg = torch.randint(0, len(entity2id), (1,), device=device)
        neg_score = model(h_t, r_t, t_neg)

        loss = -torch.log(torch.sigmoid(pos_score) + 1e-9) - torch.log(1 - torch.sigmoid(neg_score) + 1e-9)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    print(f"Epoch {epoch+1}/{epochs} — Loss: {total_loss:.4f}")

# ======================== 7. VISUALISATION t-SNE ========================
emb = model.entity_emb.weight.detach().cpu().numpy()
tsne = TSNE(n_components=2, random_state=42)
reduced = tsne.fit_transform(emb)
plt.figure(figsize=(10, 7))
plt.scatter(reduced[:, 0], reduced[:, 1], s=10, alpha=0.7)
plt.title("t-SNE des entités RotatE")
plt.savefig("data/embeddings/tsne_rotate.png")
plt.close()

# ======================== 8. SAUVEGARDE ========================
np.savez_compressed("data/embeddings/rotate_embeddings.npz", emb=emb, entity2id=entity2id)

# ======================== 9. ÉVALUATION MRR ========================
def evaluate(model, test_triples, k=10):
    model.eval()
    ranks, hits = [], 0
    for h, r, t in test_triples:
        h_t = torch.tensor([h]).to(device)
        r_t = torch.tensor([r]).to(device)
        all_t = torch.arange(len(entity2id)).to(device)
        scores = model(h_t.repeat(len(entity2id)), r_t.repeat(len(entity2id)), all_t)
        _, indices = torch.sort(scores, descending=True)
        rank = (indices == t).nonzero(as_tuple=False).item() + 1
        ranks.append(rank)
        if rank <= k:
            hits += 1
    mrr = np.mean([1.0 / r for r in ranks])
    print(f"🎯 Evaluation RotatE : MRR = {mrr:.4f}, Hits@{k} = {hits/len(test_triples):.4f}")

evaluate(model, test_triples)
