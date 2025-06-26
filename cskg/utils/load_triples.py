# ======================== load_triples.py ========================
import pandas as pd
import numpy as np
from py2neo import Graph
import os

def load_data(source="data/triples.csv"):
    """
    Charge les triplets head-relation-tail à partir d'un CSV ou de Neo4j.
    Retourne : train_triples (numpy array), test_triples, entity2id, relation2id
    """
    if source.endswith(".csv") and os.path.exists(source):
        print(f"📥 Chargement des triplets depuis {source}...")
        df = pd.read_csv(source)
    else:
        # ======================== 2. CONNEXION NEO4J ======================
        # Connexion Neo4j Aura Free avec paramètres codés en dur



        uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
        user = "neo4j"
        password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"

# Initialisation de la connexion au graphe Neo4j Aura
       graph = Graph(uri, auth=(user, password))



        query = """
        MATCH (h)-[r]->(t)
        WHERE h.name IS NOT NULL AND t.name IS NOT NULL
        RETURN h.name AS head, type(r) AS relation, t.name AS tail
        """
        df = graph.run(query).to_data_frame()
        df.to_csv("data/triples.csv", index=False)  # Sauvegarde facultative

    # Nettoyage et encodage
    df = df.dropna()
    entities = pd.Index(df["head"].tolist() + df["tail"].tolist()).unique()
    relations = pd.Index(df["relation"]).unique()
    entity2id = {e: i for i, e in enumerate(entities)}
    relation2id = {r: i for i, r in enumerate(relations)}

    # Encodage des triplets
    triples = np.array([(entity2id[h], relation2id[r], entity2id[t]) for h, r, t in df.values])
    # Séparation entraînement / test (90/10)
    split = int(0.9 * len(triples))
    return triples[:split], triples[split:], entity2id, relation2id
