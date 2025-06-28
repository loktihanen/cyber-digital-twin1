from py2neo import Graph, Node
import datetime
import nvdlib

# Connexion Neo4j
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))


# ========== 1. Vérification mise à jour NVD ==========
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
    current_cves = nvdlib.getCVE(modStartDate=(datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat())
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


# ========== 2. Imports pipeline ==========
from collect_nvd import pipeline_kg1
from inject_nessus import pipeline_kg2
from align_and_merge import (
    align_cve_nodes, fuse_cve_same_as,
    align_and_merge_vendors_products,
    update_plugin_cve_relations,
    create_network_links, recommend_patches,
    add_network_segments, debug_invalid_hosts
)


# ========== 3. Enrichissements & simulation ==========
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


# ========== 4. Visualisation Pyvis (commentée) ==========
"""
from pyvis.network import Network
import tempfile
import webbrowser

def visualize_high_risk_hosts():
    query = '''
    MATCH (h:Host)
    WHERE h.riskScore > 7
    OPTIONAL MATCH (h)-[:vulnerableTo]->(c:CVE_UNIFIED)
    RETURN h.name AS host, h.riskScore AS risk, collect(c.name) AS cves
    '''
    results = graph.run(query).data()

    net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
    net.barnes_hut()

    for row in results:
        host = row["host"]
        risk = round(row["risk"], 2)
        cves = row["cves"]

        net.add_node(host, label=f"{host}\\nRisk: {risk}", color="red", shape="dot", size=risk*4)

        for cve in cves:
            net.add_node(cve, label=cve, color="orange", shape="box", size=10)
            net.add_edge(host, cve)

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as f:
        net.show(f.name)
        webbrowser.open("file://" + f.name")
"""

# ========== 5. Alerte email (commentée) ==========
"""
import smtplib
from email.mime.text import MIMEText

FROM_EMAIL = "ton.email@gmail.com"
TO_EMAIL = "destinataire@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
APP_PASSWORD = "motdepasse_application"

def send_alert_email(message):
    msg = MIMEText(message)
    msg["Subject"] = "⚠️ Alerte cybersécurité – Hôtes à haut risque détectés"
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(FROM_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        print("📧 Email d'alerte envoyé !")

def send_email_alerts_for_high_risk_hosts():
    query = '''
    MATCH (h:Host)
    WHERE h.riskScore > 8
    RETURN h.name AS host, h.riskScore AS score
    ORDER BY h.riskScore DESC
    '''
    results = graph.run(query).data()
    if results:
        msg = "Hôtes à haut risque détectés :\\n\\n"
        for r in results:
            msg += f"• {r['host']} – Risk: {round(r['score'], 2)}\\n"
        send_alert_email(msg)
    else:
        print("✅ Aucun hôte en alerte critique.")
"""


# ========== 6. Pipeline principal ==========
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

        # visualize_high_risk_hosts()  # 🔍 Active pour voir les hôtes à risque
        # send_email_alerts_for_high_risk_hosts()  # ✉️ Active pour alerte email
    else:
        print("📉 Pas de traitement : la NVD n’a pas été mise à jour.")


# ========== 7. Exécution ==========
if __name__ == "__main__":
    main()
