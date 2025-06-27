# ======================== 1. INSTALLATION ========================
# Assure-toi d'avoir les bonnes versions
# !pip install py2neo rdflib owlrl kafka-python networkx matplotlib --quiet

# ======================== 2. IMPORTS ========================
from py2neo import Graph as NeoGraph
from rdflib import Graph, Namespace, RDF, RDFS, OWL, Literal
from owlrl import DeductiveClosure, OWLRL_Semantics
from rdflib.plugins.sparql import prepareQuery
from kafka import KafkaProducer
import json
import networkx as nx
import matplotlib.pyplot as plt

# ======================== 3. CONNEXION NEO4J ========================

uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"

# Connexion py2neo correcte : on passe le user/password en paramètre auth (tuple)
# Le constructeur accepte : Graph(uri, auth=(user, password))
# Mais l'erreur semble indiquer que ta version de py2neo ne le supporte pas
# Solution : passer l'URI avec user:password@host ou utiliser la classe Auth

# Variante compatible (avec py2neo >=4):
neo_graph = NeoGraph(uri, auth=(user, password))

try:
    info = neo_graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# ======================== 4. CRÉATION ONTOLOGIE RDF ========================

rdf_graph = Graph()
CYBER = Namespace("http://example.org/cyber#")
rdf_graph.bind("cyber", CYBER)

# Classes
new_classes = [
    ("AttackPath", CYBER.AttackPath),
    ("SecurityControl", CYBER.SecurityControl),
    ("CriticalAsset", CYBER.CriticalAsset),
    ("NetworkSegment", CYBER.NetworkSegment)
]

# Propriétés
new_properties = [
    ("at_risk_of", CYBER.at_risk_of),
    ("needs_patch", CYBER.needs_patch),
    ("protected_by", CYBER.protected_by),
    ("targets", CYBER.targets),
    ("exposed_to", CYBER.exposed_to),
    ("connected_to", CYBER.connected_to)
]

for label, uri in new_classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

for label, uri in new_properties:
    rdf_graph.add((uri, RDF.type, OWL.ObjectProperty))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="cskg3_enriched.ttl", format="turtle")
print("✅ Ontologie enrichie enregistrée dans cskg3_enriched.ttl")

# ======================== 5. RAISONNEMENT OWL ========================

g = Graph()
g.parse("cskg3_enriched.ttl", format="turtle")

DeductiveClosure(OWLRL_Semantics).expand(g)

g.serialize(destination="cskg3_inferenced.ttl", format="turtle")
print("✅ Inférences OWL appliquées et enregistrées dans cskg3_inferenced.ttl")

# ======================== 6. REQUÊTE SPARQL ========================

query = prepareQuery("""
PREFIX cyber: <http://example.org/cyber#>
SELECT ?asset ?cve WHERE {
    ?asset cyber:at_risk_of ?cve .
}
""")

print("\n🔍 Actifs critiques à risque :")
for row in g.query(query):
    print(f" - {row.asset.split('#')[-1]} est à risque de {row.cve.split('#')[-1]}")

# ======================== 7. TRIGGER NEO4J (à exécuter dans Neo4j Browser) ========================
# CALL apoc.trigger.add('alertCriticalCVE',
#   "MATCH (h:Host)-[:VULNERABLE_TO]->(c:CVE)
#    WHERE c.severity = 'CRITICAL'
#    CALL apoc.log.info('⚠️ Host à risque : ' + h.name + ' via ' + c.name)
#    RETURN true",
#   {phase:'after'})

# ======================== 8. STREAMING AVEC KAFKA ========================

#producer = KafkaProducer(
    #bootstrap_servers='localhost:9092',
  #  value_serializer=lambda m: json.dumps(m).encode('utf-8')
#)

#event = {
  #  "host": "host-001",
  #  "cve": "CVE-2024-12345",
 #   "severity": "CRITICAL"
#}

#producer.send("cskg-alerts", value=event)
#print("📤 Alerte envoyée à Kafka :", event)

# ======================== 9. SIMULATION CHAÎNE D'ATTAQUE ========================

G_nx = nx.DiGraph()

attack_chain = [
    ("host-001", "connected_to", "host-002"),
    ("host-002", "connected_to", "host-003"),
    ("host-003", "at_risk_of", "CVE-2024-99999"),
    ("CVE-2024-99999", "targets", "CriticalAsset-01")
]

for h, r, t in attack_chain:
    G_nx.add_edge(h, t, label=r)

pos = nx.spring_layout(G_nx)
nx.draw(G_nx, pos, with_labels=True, node_color='lightcoral', edge_color='gray', node_size=2000, font_size=9)
edge_labels = nx.get_edge_attributes(G_nx, 'label')
nx.draw_networkx_edge_labels(G_nx, pos, edge_labels=edge_labels)
plt.title("🔗 Chaîne d'attaque simulée")
plt.show()

# ======================== 10. VALIDATION ACADÉMIQUE ========================

same_as_count = neo_graph.evaluate("MATCH (:CVE)-[:SAME_AS]->(:CVE) RETURN count(*)")
total_cves = neo_graph.evaluate("MATCH (c:CVE) RETURN count(c)")

print(f"\n📊 Taux d’alignement SAME_AS : {same_as_count}/{total_cves} = {same_as_count/total_cves:.2%}")

critical_alerts = neo_graph.evaluate("MATCH (h:Host)-[:VULNERABLE_TO]->(c:CVE) WHERE c.severity = 'CRITICAL' RETURN count(*)")
print(f"🚨 Nombre d’alertes critiques détectées : {critical_alerts}")

