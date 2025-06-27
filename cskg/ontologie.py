# ======================== 1. INSTALLATION ========================
#!pip install rdflib owlrl kafka-python --quiet
from rdflib import Graph, Namespace, RDF, RDFS, OWL, Literal

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


# ======================== 2. ONTOLOGIE CSKG3 ========================


rdf_graph = Graph()
CYBER = Namespace("http://example.org/cyber#")
rdf_graph.bind("cyber", CYBER)

# Nouvelles classes
new_classes = [
    ("AttackPath", CYBER.AttackPath),
    ("SecurityControl", CYBER.SecurityControl),
    ("CriticalAsset", CYBER.CriticalAsset),
    ("NetworkSegment", CYBER.NetworkSegment)
]

# Nouvelles propriétés
new_properties = [
    ("at_risk_of", CYBER.at_risk_of),
    ("needs_patch", CYBER.needs_patch),
    ("protected_by", CYBER.protected_by),
    ("targets", CYBER.targets),
    ("exposed_to", CYBER.exposed_to),
    ("connected_to", CYBER.connected_to)
]

# Ajout des classes
for label, uri in new_classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

# Ajout des relations
for label, uri in new_properties:
    rdf_graph.add((uri, RDF.type, OWL.ObjectProperty))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="cskg3_enriched.ttl", format="turtle")
print("✅ Ontologie enrichie enregistrée dans cskg3_enriched.ttl")

# ======================== 3. RAISONNEMENT OWL ========================
from owlrl import DeductiveClosure, OWLRL_Semantics

# Charger l'ontologie
g = Graph()
g.parse("cskg3_enriched.ttl", format="turtle")

DeductiveClosure(OWLRL_Semantics).expand(g)
g.serialize(destination="cskg3_inferenced.ttl", format="turtle")
print("✅ Inférences OWL appliquées et enregistrées dans cskg3_inferenced.ttl")

# ======================== 4. VISUALISATION DES INFÉRENCES ========================
from rdflib.plugins.sparql import prepareQuery

query = prepareQuery("""
PREFIX cyber: <http://example.org/cyber#>
SELECT ?asset ?cve WHERE {
    ?asset cyber:at_risk_of ?cve .
}
""")

print("\n🔍 Actifs critiques à risque :")
for row in g.query(query):
    print(f" - {row.asset.split('#')[-1]} est à risque de {row.cve.split('#')[-1]}")

# ======================== 5. TRIGGER NEO4J ========================
# A exécuter dans Neo4j Browser :
# CALL apoc.trigger.add('alertCriticalCVE',
#   "MATCH (h:Host)-[:VULNERABLE_TO]->(c:CVE)
#    WHERE c.severity = 'CRITICAL'
#    CALL apoc.log.info('⚠️ Host à risque : ' + h.name + ' via ' + c.name)
#    RETURN true",
#   {phase:'after'})

# ======================== 6. STREAM ALERTES AVEC KAFKA ========================
from kafka import KafkaProducer
import json

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda m: json.dumps(m).encode('utf-8')
)

event = {
    "host": "host-001",
    "cve": "CVE-2024-12345",
    "severity": "CRITICAL"
}

producer.send("cskg-alerts", value=event)
print("📤 Alerte envoyée à Kafka :", event)

# ======================== 7. SIMULATION CHAÎNE D'ATTAQUE ========================
import networkx as nx
import matplotlib.pyplot as plt

G = nx.DiGraph()

# Exemple simplifié de chaîne d’attaque simulée
attack_chain = [
    ("host-001", "connected_to", "host-002"),
    ("host-002", "connected_to", "host-003"),
    ("host-003", "at_risk_of", "CVE-2024-99999"),
    ("CVE-2024-99999", "targets", "CriticalAsset-01")
]

for h, r, t in attack_chain:
    G.add_edge(h, t, label=r)

# Affichage
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_color='lightcoral', edge_color='gray', node_size=2000, font_size=9)
edge_labels = nx.get_edge_attributes(G, 'label')
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
plt.title("🔗 Chaîne d'attaque simulée")
plt.show()

# ======================== 8. VALIDATION ACADÉMIQUE ========================
# Mesure de l’alignement via ratio des SAME_AS entre CVEs des sources différentes
from py2neo import Graph as NeoGraph

neo_graph = NeoGraph("neo4j+s://8d5fbce8.databases.neo4j.io", auth=("neo4j", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"))

same_as_count = neo_graph.evaluate("MATCH (:CVE)-[:SAME_AS]->(:CVE) RETURN count(*)")
total_cves = neo_graph.evaluate("MATCH (c:CVE) RETURN count(c)")

print(f"\n📊 Taux d’alignement SAME_AS : {same_as_count}/{total_cves} = {same_as_count/total_cves:.2%}")

# Nombre d’alertes critiques
critical_alerts = neo_graph.evaluate("MATCH (h:Host)-[:VULNERABLE_TO]->(c:CVE) WHERE c.severity = 'CRITICAL' RETURN count(*)")
print(f"🚨 Nombre d’alertes critiques détectées : {critical_alerts}")
