from py2neo import Graph, Node
import datetime
import nvdlib

# ======================== 1. Connexion Neo4j ========================
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))
print("✅ Connexion Neo4j réussie")

# ======================== 2. Vérification mise à jour NVD ========================
def get_last_nvd_update_in_graph():
    node = graph.nodes.match("UpdateLog", name="NVD").first()
    return node["last_nvd_update"] if node else None

def set_last_nvd_update_in_graph(timestamp):
    node = graph.nodes.match("UpdateLog", name="NVD").first()
    if not node:
        node = Node("UpdateLog", name="NVD")
        graph.create(node)
    node["last_nvd_update"] = timestamp
    graph.push(node)
from datetime import datetime, timedelta

from datetime import datetime, timedelta
import nvdlib

def is_nvd_updated():
    print("🔎 Vérification des mises à jour NVD...")

    last = get_last_nvd_update_in_graph()
    mod_start = (datetime.utcnow() - timedelta(days=1)).replace(microsecond=0)
    mod_end = datetime.utcnow().replace(microsecond=0)

    try:
        current_cves = list(nvdlib.searchCVE(
            lastModStartDate=mod_start.isoformat() + "Z",
            lastModEndDate=mod_end.isoformat() + "Z",
            limit=1000  # ✅ pas `resultsPerPage`
        ))
    except Exception as e:
        print("❌ Erreur lors de l’appel à nvdlib.searchCVE() :", e)
        raise e

    if not current_cves:
        print("⚠️ Aucune CVE récupérée via NVDLIB.")
        return False

    latest_cve = max([cve.lastModified for cve in current_cves])
    if latest_cve and (not last or latest_cve > last):
        print(f"🆕 Mise à jour détectée dans la NVD : {latest_cve}")
        set_last_nvd_update_in_graph(latest_cve)
        return True

    print("✅ Pas de nouvelle mise à jour NVD.")
    return False



# ======================== 3. Imports pipeline ========================
from collect_nvd import pipeline_kg1
from inject_nessus import pipeline_kg2
from align_and_merge import (
    align_cve_nodes, fuse_cve_same_as,
    align_and_merge_vendors_products,
    update_plugin_cve_relations,
    create_network_links, recommend_patches,
    add_network_segments, debug_invalid_hosts
)

# ======================== 4. Étapes du pipeline ========================
def enrich_graph():
    print("🧠 Étape 4 : Enrichissements intelligents")
    align_and_merge_vendors_products()
    update_plugin_cve_relations()
    create_network_links()
    recommend_patches()
    add_network_segments()
    debug_invalid_hosts()
    print("✅ Enrichissement complet effectué.")

def update_nessus_from_new_cves():
    print("💥 Étape 5 : Simulation des impacts des nouvelles CVE sur les hôtes")
    query = """
    MATCH (c:CVE_UNIFIED)-[:SAME_AS]->(:CVE)<-[:detects]-(p:Plugin)<-[:runsPlugin]-(h:Host)
    MERGE (h)-[:vulnerableTo]->(c)
    """
    graph.run(query)
    print("✅ Hôtes Nessus mis à jour avec les nouvelles vulnérabilités")

def simulate_risk_per_host():
    print("🧮 Étape 6 : Simulation de risque par hôte")
    query = """
    MATCH (h:Host)-[:vulnerableTo]->(c:CVE_UNIFIED)
    WHERE exists(c.cvssScore)
    WITH h, avg(toFloat(c.cvssScore)) AS avgRisk, count(c) AS vulnCount
    SET h.riskScore = avgRisk, h.vulnerabilityCount = vulnCount
    RETURN h.name AS host, avgRisk AS averageRisk, vulnCount
    ORDER BY avgRisk DESC
    """
    results = graph.run(query).data()
    print("📊 Résultats de la simulation de risque :")
    for row in results:
        print(f"🔹 {row['host']} → Risk: {round(row['averageRisk'],2)} ({row['vulnCount']} vulnérabilités)")
    print("✅ Scores de risque mis à jour dans Neo4j.")

# ======================== 5. Pipeline principal ========================
def main():
    if is_nvd_updated():
        print("\n🚀 Étape 1 : Reconstruction de CSKG1 (NVD)")
        pipeline_kg1(start=0, results_per_page=2000)

        print("\n⚙️ Étape 2 : Reconstruction de CSKG2 (Nessus)")
        pipeline_kg2()

        print("\n🔗 Étape 3 : Alignement & Fusion CSKG1 + CSKG2")
        align_cve_nodes()
        fuse_cve_same_as()

        enrich_graph()
        update_nessus_from_new_cves()
        simulate_risk_per_host()
    else:
        print("📉 Pas de traitement : la NVD n’a pas été mise à jour.")

# ======================== 6. Exécution ========================
if __name__ == "__main__":
    main()
