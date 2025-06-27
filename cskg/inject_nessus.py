# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
import pandas as pd
import os

# ======================== 2. CONNEXION NEO4J =======================
# Connexion Neo4j Aura Free avec paramètres codés en dur
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


# ======================== 3. CHARGEMENT CSV NESSUS ========================
NESSUS_CSV_PATH = "data/nessuss-scan1.csv"

def load_nessus_data(path):
    df = pd.read_csv(path)
    df = df.fillna("")  # éviter les NaN
    return df

# ======================== 4. INJECTION DANS NEO4J ========================
def inject_nessus_to_neo4j(df):
    for idx, row in df.iterrows():
        host_ip = row.get("Host", "")
        plugin_id = str(row.get("Plugin ID", "")).strip()
        plugin_name = row.get("Name", "")
        port = str(row.get("Port", ""))
        protocol = row.get("Protocol", "")
        service = row.get("Service", "")
        os_name = row.get("Operating System", "")
        severity = row.get("Severity", "")
        scanner = row.get("Scanner", "Nessus")
        cve_list = str(row.get("CVE", "")).split(",")

        # 🔹 Noeud Host
        host_node = Node("Host", name=host_ip)
        graph.merge(host_node, "Host", "name")

        # 🔹 Noeud Plugin
        plugin_node = Node("Plugin", id=plugin_id, name=plugin_name)
        graph.merge(plugin_node, "Plugin", "id")

        # 🔹 Port
        if port:
            port_node = Node("Port", number=port, protocol=protocol)
            graph.merge(port_node, "Port", "number")
            graph.merge(Relationship(host_node, "EXPOSES", port_node))
            graph.merge(Relationship(port_node, "RUNS_PLUGIN", plugin_node))
        else:
            graph.merge(Relationship(host_node, "RUNS_PLUGIN", plugin_node))

        # 🔹 Service
        if service:
            service_node = Node("Service", name=service)
            graph.merge(service_node, "Service", "name")
            graph.merge(Relationship(host_node, "HAS_SERVICE", service_node))
            if port:
                graph.merge(Relationship(service_node, "RUNS_ON_PORT", port_node))

        # 🔹 Operating System
        if os_name:
            os_node = Node("OperatingSystem", name=os_name)
            graph.merge(os_node, "OperatingSystem", "name")
            graph.merge(Relationship(host_node, "HAS_OS", os_node))

        # 🔹 Scanner
        if scanner:
            scanner_node = Node("Scanner", name=scanner)
            graph.merge(scanner_node, "Scanner", "name")
            graph.merge(Relationship(host_node, "SCANNED_BY", scanner_node))

        # 🔹 CVE(s)
        for cve in cve_list:
            cve = cve.strip()
            if cve.startswith("CVE-"):
                cve_node = Node("CVE", name=cve, source="Nessus")
                graph.merge(cve_node, "CVE", "name")
                graph.merge(Relationship(plugin_node, "DETECTS", cve_node))
                graph.merge(Relationship(host_node, "VULNERABLE_TO", cve_node))

        # 🔹 Severity
        if severity:
            severity_node = Node("Severity", level=severity)
            graph.merge(severity_node, "Severity", "level")
            graph.merge(Relationship(host_node, "HAS_SEVERITY", severity_node))

# ======================== 5. PIPELINE ========================
def pipeline_kg2():
    print("📥 Chargement des données Nessus...")
    df = load_nessus_data(NESSUS_CSV_PATH)
    print(f"📊 {len(df)} lignes détectées.")
    inject_nessus_to_neo4j(df)
    print("✅ Données Nessus injectées dans le graphe.")

# ======================== 6. EXÉCUTION ========================
if __name__ == "__main__":
    pipeline_kg2()
