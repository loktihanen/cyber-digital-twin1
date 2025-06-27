from py2neo import Graph
import csv

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

# Requête Cypher pour récupérer tous les triplets (source, relation, cible)
query = """
MATCH (h)-[r]->(t)
WHERE
  h.name IS NOT NULL AND
  t.name IS NOT NULL
RETURN h.name AS head, type(r) AS relation, t.name AS tail
"""

results = graph.run(query).data()

# Export en TSV
with open("cskg3_triples.tsv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f, delimiter="\t")
    for row in results:
        writer.writerow([row['head'], row['relation'], row['tail']])

print(f"✅ {len(results)} triplets exportés dans cskg3_triples.tsv")
