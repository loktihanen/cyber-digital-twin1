# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
import requests
import time
import os

# ======================== 2. CONNEXION NEO4J =======================

uri = os.environ.get("NEO4J_URI")
user = os.environ.get("NEO4J_USER")
password = os.environ.get("NEO4J_PASSWORD")

graph = Graph(uri, auth=(user, password))


# ======================== 3. ONTOLOGIE RDF ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

classes = [
    ("CVE", STUCO.Vulnerability), ("CWE", STUCO.Weakness), ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity)
]
for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="kg1.ttl", format="turtle")

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. API NVD ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 6. INSERTION DANS NEO4J ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published:
        cve_node["published"] = published

    try:
        metrics = item["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cve_node["cvss_score"] = data["baseScore"]
            cve_node["severity"] = data["baseSeverity"]
            cve_node["attackVector"] = data.get("attackVector")
            cve_node["privilegesRequired"] = data.get("privilegesRequired")
            cve_node["userInteraction"] = data.get("userInteraction")
            cve_node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ Problème CVSS sur {cve_id} : {e}")

    graph.merge(cve_node, "CVE", "name")

    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                existing = graph.nodes.match("CWE", name=cwe_id).first()
                cwe_node = existing if existing else Node("CWE", name=cwe_id)
                if not existing:
                    graph.create(cwe_node)
                graph.merge(Relationship(cve_node, "ASSOCIATED_WITH", cwe_node))

    try:
        nodes = item["cve"]["configurations"][0]["nodes"]
        for config in nodes:
            for cpe in config.get("cpeMatch", []):
                cpe_uri = cpe["criteria"]
                cpe_node = Node("CPE", name=cpe_uri)
                graph.merge(cpe_node, "CPE", "name")
                graph.merge(Relationship(cve_node, "AFFECTS", cpe_node))
    except Exception:
        pass

    try:
        entities = ner(description)
        for ent in entities:
            word = ent["word"]
            ent_type = ent["entity_group"]
            ent_node = Node("Entity", name=word, type=ent_type)
            graph.merge(ent_node, "Entity", "name")
            graph.merge(Relationship(cve_node, "MENTIONS", ent_node))
    except Exception as e:
        print(f"⚠️ NER erreur sur {cve_id}: {e}")

# ======================== 7. PIPELINE ========================
def pipeline_kg1(start=0, results_per_page=10):
    print("🚀 Extraction CVE depuis NVD...")
    data = fetch_cve_nvd(start=start, results_per_page=results_per_page)
    for item in data.get("vulnerabilities", []):
        try:
            insert_cve_neo4j(item)
            time.sleep(0.2)
        except Exception as e:
            print(f"[!] Erreur {item['cve']['id']}: {e}")
    print("✅ KG1 inséré dans Neo4j.")

# ======================== 8. EXÉCUTION ========================
if __name__ == "__main__":
    pipeline_kg1(start=0, results_per_page=20)

