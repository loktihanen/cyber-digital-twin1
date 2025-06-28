# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal, URIRef
import pandas as pd
import os
from datetime import datetime

# ======================== 2. CONNEXION NEO4J ========================
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# ======================== 3. ONTOLOGIE RDF ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

classes = [
    ("Host", CYBER.Host), ("Port", CYBER.Port), ("Service", CYBER.Service),
    ("OperatingSystem", CYBER.OperatingSystem), ("Plugin", CYBER.Plugin),
    ("Scanner", CYBER.Scanner), ("Severity", CYBER.Severity), ("CVE", STUCO.Vulnerability)
]

relations = [
    ("vulnerableTo", CYBER.vulnerable_to),
    ("hasService", CYBER.has_service),
    ("runsOnPort", CYBER.runs_on_port),
    ("hasOS", CYBER.has_OS),
    ("detectedBy", CYBER.detected_by),
    ("hasSeverity", CYBER.has_severity),
    ("scannedBy", CYBER.scanned_by),
    ("exposes", CYBER.exposes),
    ("runsPlugin", CYBER.runs_plugin),
    ("hasCVE", CYBER.hasCVE)
]

for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

for label, uri in relations:
    rdf_graph.add((uri, RDF.type, OWL.ObjectProperty))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="kg2.ttl", format="turtle")
print("✅ Ontologie KG2 RDF exportée : kg2.ttl")

# ======================== 4. CHARGEMENT CSV NESSUS ========================
NESSUS_CSV_PATH = "data/nessuss-scan1.csv"

def load_nessus_data(path):
    df = pd.read_csv(path)
    df = df.fillna("")  # Évite les NaN
    return df

# ======================== 5. INJECTION DANS NEO4J ========================
def inject_nessus_to_neo4j(df):
    # Date de mise à jour (aujourd'hui) pour lastUpdated
    update_date = datetime.utcnow().isoformat()

    for idx, row in df.iterrows():
        host_ip = row.get("Host", "").strip()
        plugin_id = str(row.get("Plugin ID", "")).strip()
        plugin_name = row.get("Name", "").strip()
        port = str(row.get("Port", "")).strip()
        protocol = row.get("Protocol", "").strip()
        service = row.get("Service", "").strip()
        os_name = row.get("Operating System", "").strip()
        severity = row.get("Risk", row.get("Risk Factor", "")).strip()
        scanner = row.get("Scanner", "Nessus").strip()
        cve_list = str(row.get("CVE", "")).split(",")

        if not host_ip:
            continue  # Ignore les lignes sans hôte

        # 🔹 Host
        host_node = Node("Host", name=host_ip, source="Nessus", lastUpdated=update_date)
        host_node["uri"] = f"http://example.org/host/{host_ip}"
        graph.merge(host_node, "Host", "name")

        # 🔹 Plugin
        plugin_node = Node("Plugin", id=plugin_id, name=plugin_name, source="Nessus", lastUpdated=update_date)
        plugin_node["uri"] = f"http://example.org/plugin/{plugin_id}"
        graph.merge(plugin_node, "Plugin", "id")

        # 🔹 Port
        if port:
            port_node = Node("Port", number=port, protocol=protocol, source="Nessus", lastUpdated=update_date)
            port_node["uri"] = f"http://example.org/port/{host_ip}_{port}"
            graph.merge(port_node, "Port", "number")
            graph.merge(Relationship(host_node, "exposes", port_node))
            graph.merge(Relationship(port_node, "runsPlugin", plugin_node))
        else:
            graph.merge(Relationship(host_node, "runsPlugin", plugin_node))

        # 🔹 Service
        if service:
            service_node = Node("Service", name=service, source="Nessus", lastUpdated=update_date)
            service_node["uri"] = f"http://example.org/service/{service.replace(' ', '_')}"
            graph.merge(service_node, "Service", "name")
            graph.merge(Relationship(host_node, "hasService", service_node))
            if port:
                graph.merge(Relationship(service_node, "runsOnPort", port_node))

        # 🔹 OS
        if os_name:
            os_node = Node("OperatingSystem", name=os_name, source="Nessus", lastUpdated=update_date)
            os_node["uri"] = f"http://example.org/os/{os_name.replace(' ', '_')}"
            graph.merge(os_node, "OperatingSystem", "name")
            graph.merge(Relationship(host_node, "hasOS", os_node))

        # 🔹 Scanner
        if scanner:
            scanner_node = Node("Scanner", name=scanner, source="Nessus", lastUpdated=update_date)
            scanner_node["uri"] = f"http://example.org/scanner/{scanner.replace(' ', '_')}"
            graph.merge(scanner_node, "Scanner", "name")
            graph.merge(Relationship(host_node, "scannedBy", scanner_node))

        # 🔹 CVEs
        for cve in cve_list:
            cve = cve.strip()
            if cve.startswith("CVE-"):
                cve_node = Node("CVE", name=cve, source="Nessus", lastUpdated=update_date)
                cve_node["uri"] = f"http://example.org/cve/{cve}"
                graph.merge(cve_node, "CVE", "name")
                graph.merge(Relationship(plugin_node, "detects", cve_node))
                graph.merge(Relationship(host_node, "vulnerableTo", cve_node))
                # Relation inverse Plugin -> CVE pour harmonisation
                graph.merge(Relationship(plugin_node, "hasCVE", cve_node))

        # 🔹 Sévérité
        if severity:
            severity_node = Node("Severity", level=severity, source="Nessus", lastUpdated=update_date)
            severity_node["uri"] = f"http://example.org/severity/{severity.replace(' ', '_')}"
            graph.merge(severity_node, "Severity", "level")
            graph.merge(Relationship(host_node, "hasSeverity", severity_node))

# ======================== 6. PIPELINE ========================
def pipeline_kg2():
    print("📥 Chargement des données Nessus...")
    df = load_nessus_data(NESSUS_CSV_PATH)
    print(f"📊 {len(df)} lignes détectées.")
    inject_nessus_to_neo4j(df)
    print("✅ Données Nessus injectées dans Neo4j.")

# ======================== 7. EXECUTION ========================
if __name__ == "__main__":
    pipeline_kg2()
