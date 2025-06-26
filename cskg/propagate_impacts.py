# ======================== 1. IMPORTS ========================
from py2neo import Graph, Relationship
import os

# ======================== 2. CONNEXION NEO4J ========================
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")
graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ======================== 3. PROPAGATION DES IMPACTS ========================
def propagate_impacts():
    print("📡 Début de la propagation des impacts...")

    query = """
    MATCH (h:Host)-[:RUNS_PLUGIN|EXPOSES|RUNS]->(p:Plugin)-[:DETECTS]->(c:CVE)
    OPTIONAL MATCH (c)-[:SAME_AS]->(c2:CVE)
    WITH DISTINCT h, c, c2,
         coalesce(c.cvss_score, c2.cvss_score, 5.0) AS score,
         coalesce(c.severity, c2.severity, "MEDIUM") AS severity
    MERGE (h)<-[r:IMPACTS]-(coalesce(c2, c))
    SET r.score = score,
        r.level = severity
    """

    graph.run(query)
    print("✅ Propagation des vulnérabilités vers les hôtes terminée.")

    # Optionnel : propagation vers des services
    query_services = """
    MATCH (c:CVE)-[:SAME_AS*0..1]->(cve:CVE)
    MATCH (p:Plugin)-[:DETECTS]->(cve)
    MATCH (port:Port)-[:RUNS_PLUGIN]->(p)
    MATCH (h:Host)-[:EXPOSES]->(port)
    MERGE (cve)-[:IMPACTS]->(port)
    """

    graph.run(query_services)
    print("✅ Propagation vers les services critiques terminée.")

# ======================== 4. EXÉCUTION ========================
if __name__ == "__main__":
    propagate_impacts()
