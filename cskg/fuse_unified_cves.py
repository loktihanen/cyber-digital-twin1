# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
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


# ======================== 3. FUSION DES CVE ALIGNÉES ========================
def fuse_cve_same_as():
    print("🧠 Fusion des CVE alignées via SAME_AS...")

    # 1. Trouver tous les groupes de CVE alignées
    query = """
    MATCH (c:CVE)-[:SAME_AS]->(c2:CVE)
    RETURN DISTINCT c.name AS name1, c2.name AS name2
    """

    pairs = graph.run(query).data()
    matched = set()

    for pair in pairs:
        name1, name2 = pair["name1"], pair["name2"]
        key = tuple(sorted([name1, name2]))

        if key in matched:
            continue
        matched.add(key)

        # Vérifie si un noeud fusionné existe déjà
        unified_name = name1 if name1 < name2 else name2
        unified_node = graph.nodes.match("CVE_UNIFIED", name=unified_name).first()
        if not unified_node:
            unified_node = Node("CVE_UNIFIED", name=unified_name)
            graph.create(unified_node)

        # Relier les deux CVE au noeud fusionné
        c1 = graph.nodes.match("CVE", name=name1).first()
        c2 = graph.nodes.match("CVE", name=name2).first()

        if c1:
            graph.merge(Relationship(unified_node, "SAME_AS", c1))
        if c2:
            graph.merge(Relationship(unified_node, "SAME_AS", c2))

    print(f"✅ {len(matched)} paires fusionnées dans des noeuds CVE_UNIFIED.")

# ======================== 4. EXÉCUTION ========================
if __name__ == "__main__":
    fuse_cve_same_as()
