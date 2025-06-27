# -*- coding: utf-8 -*-
"""
Cybersecurity Knowledge Graph - Query & Reasoning
This script performs:
1. SPARQL queries on a fused RDF graph (CSKG3)
2. Structural analysis and simulation on a Neo4j graph
"""

# ============================================================
# Part 1: SPARQL Queries on RDF Graph (CSKG3)
# ============================================================

from rdflib import Graph, Namespace

# Load the RDF graph (CSKG3)
kg3 = Graph()
kg3.parse("cskg3.ttl", format="turtle")

# Bind namespaces
CYBER = Namespace("http://example.org/cyber#")
kg3.bind("cyber", CYBER)

# Query 1: Hosts with critical unpatched vulnerabilities
q1 = """
PREFIX cyber: <http://example.org/cyber#>
SELECT DISTINCT ?host WHERE {
  ?host cyber:vulnerable_to ?cve .
  ?cve cyber:has_severity "Critical" .
  FILTER NOT EXISTS {
    ?cve cyber:mitigated_by ?patch .
  }
}
"""

# Query 2: Communication chains between hosts
q2 = """
PREFIX cyber: <http://example.org/cyber#>
SELECT ?src ?dst WHERE {
  ?src cyber:communicates_with ?dst .
}
"""

# Query 3: Network segments with highest critical risk
q3 = """
PREFIX cyber: <http://example.org/cyber#>
SELECT ?segment (COUNT(?cve) AS ?cve_count) WHERE {
  ?host cyber:in_segment ?segment .
  ?host cyber:vulnerable_to ?cve .
  ?cve cyber:has_severity "Critical" .
}
GROUP BY ?segment ORDER BY DESC(?cve_count)
"""

# Execute queries
print("⚠️ Hosts with unpatched critical CVEs:")
for r in kg3.query(q1):
    print(" -", r.host)

print("\n🔗 Inter-host communication paths:")
for r in kg3.query(q2):
    print(f" - {r.src} → {r.dst}")

print("\n🔥 High-risk network segments:")
for r in kg3.query(q3):
    print(f" - {r.segment} : {r.cve_count} critical CVEs")


# ============================================================
# Part 2: Reasoning and Attack Simulation on Neo4j Graph
# ============================================================

import networkx as nx
from py2neo import Graph as NeoGraph

# Connect to Neo4j
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


# Retrieve all relationships from the graph
records = neo_graph.run("""
MATCH (a)-[r]->(b)
RETURN a.name AS src, type(r) AS rel, b.name AS dst
""").data()

# Build a directed graph using NetworkX
G = nx.DiGraph()
for r in records:
    if r["src"] and r["dst"]:
        G.add_edge(r["src"], r["dst"], label=r["rel"])

# Detect suspicious nodes (isolated or overly connected)
degrees = G.degree()
suspicious = [n for n, d in degrees if d == 0 or d >= 8]

print("\n🚨 Suspicious nodes (isolated or over-connected):")
for n in suspicious:
    print(" -", n)

# Simulate attack propagation from a source host
def simulate_propagation(source_host, max_depth=3):
    print(f"\n🧠 Simulating propagation from {source_host} (≤ {max_depth} hops):")
    paths = nx.single_source_shortest_path(G, source=source_host, cutoff=max_depth)
    for target, path in paths.items():
        if target != source_host:
            print(f" - {source_host} → {target} | Path: {path}")

simulate_propagation("host-001")
