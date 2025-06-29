from py2neo import Graph, Node
from py2neo.errors import ServiceUnavailable
from datetime import datetime, timedelta
import nvdlib
import os
import time

# ======================== 1. Connexion Neo4j ========================
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"

def connect_to_neo4j():
    return Graph(uri, auth=(user, password))

graph = connect_to_neo4j()
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

def is_nvd_updated():
    print("🔎 Vérification des mises à jour NVD...")
    last = get_last_nvd_update_in_graph()
    mod_start = (datetime.utcnow() - timedelta(days=1)).replace(second=0, microsecond=0)
    mod_end = datetime.utcnow().replace(second=0, microsecond=0)

    try:
        current_cves = list(nvdlib.searchCVE(
            lastModStartDate=mod_start.strftime("%Y-%m-%d %H:%M"),
            lastModEndDate=mod_end.strftime("%Y-%m-%d %H:%M"),
            limit=1000
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

# ======================== 3. Vérification mise à jour Nessus ========================
def get_last_nessus_update_in_graph():
    node = graph.nodes.match("UpdateLog", name="NESSUS").first()
    return node["last_nessus_update"] if node else None

def set_last_nessus_update_in_graph(timestamp):
    node = graph.nodes.match("UpdateLog", name="NESSUS").first()
    if not node:
        node = Node("UpdateLog", name="NESSUS")
        graph.create(node)
    node["last_nessus_update"] = timestamp
    graph.push(node)

def is_nessus_updated():
    print("🔎 Vérification des mises à jour Nessus...")
    csv_path = "data/nessuss-scan1.csv"
    if not os.path.exists(csv_path):
        print("❌ Fichier Nessus introuvable :", csv_path)
        return False

    last_csv_mod = datetime.utcfromtimestamp(os.path.getmtime(csv_path))
    last_logged = get_last_nessus_update_in_graph()

    if not last_logged or last_csv_mod > last_logged:
        print(f"🆕 Mise à jour détectée dans les résultats Nessus : {last_csv_mod}")
        set_last_nessus_update_in_graph(last_csv_mod)
        return True

    print("✅ Pas de nouveau scan Nessus détecté.")
    return False

# ======================== 4. Imports pipeline ========================
from collect_nvd import pipeline_kg1
from inject_nessus import pipeline_kg2
from align_and_merge import (
    align_cve_nodes, fuse_cve_same_as,
    align_and_merge_vendors_products,
    update_plugin_cve_relations,
    create_network_links, recommend_patches,
    add_network_segments, debug_invalid_hosts
)

# ======================== 5. Requête Cypher avec reconnexion ========================
def safe_run_query(graph, query, parameters=None, retries=3):
    for attempt in range(retries):
        try:
            return graph.run(query, parameters).data()
        except ServiceUnavailable as e:
            print(f"❌ Erreur de connexion Neo4j (tentative {attempt+1}) : {e}")
            if attempt < retries - 1:
                print("🔄 Reconnexion à Neo4j...")
                time.sleep(2)
                graph = connect_to_neo4j()
            else:
                raise
    return []

# ======================== 6. Étapes du pipeline ========================
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
    safe_run_query(graph, query)
    print("✅ Hôtes Nessus mis à jour avec les nouvelles vulnérabilités")

def simulate_risk_per_host():
    print("🧮 Étape 6 : Simulation de risque par hôte")
    query = """
    MATCH (h:Host)-[:vulnerableTo]->(c:CVE_UNIFIED)
    WHERE c.cvssScore IS NOT NULL
    WITH h, avg(toFloat(c.cvssScore)) AS avgRisk, count(c) AS vulnCount
    SET h.riskScore = avgRisk, h.vulnerabilityCount = vulnCount
    RETURN h.name AS host, avgRisk AS averageRisk, vulnCount
    ORDER BY avgRisk DESC
    """
    results = safe_run_query(graph, query)
    print("📊 Résultats de la simulation de risque :")
    for row in results:
        print(f"🔹 {row['host']} → Risk: {round(row['averageRisk'],2)} ({row['vulnCount']} vulnérabilités)")
    print("✅ Scores de risque mis à jour dans Neo4j.")


# ======================== 7. Pipeline principal ========================
def main():
    nvd_flag = is_nvd_updated()
    nessus_flag = is_nessus_updated()

    if nvd_flag or nessus_flag:
        if nvd_flag:
            print("\n🚀 Étape 1 : Reconstruction de CSKG1 (NVD)")
            pipeline_kg1(start=0, results_per_page=2000)

        if nessus_flag:
            print("\n⚙️ Étape 2 : Reconstruction de CSKG2 (Nessus)")
            pipeline_kg2(graph)

        print("\n🔗 Étape 3 : Alignement & Fusion CSKG1 + CSKG2")
        align_cve_nodes()
        fuse_cve_same_as()

        enrich_graph()
        update_nessus_from_new_cves()
        simulate_risk_per_host()
    else:
        print("📉 Pas de traitement : ni la NVD ni Nessus n’ont été mis à jour.")

# ======================== 8. Exécution ========================
if __name__ == "__main__":
    main()
