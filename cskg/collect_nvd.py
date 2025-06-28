 # ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
try:
    import numpy as np
    print("✅ NumPy loaded:", np.__version__)
except ImportError as e:
    print("❌ NumPy not available:", e)
    raise e

from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal, URIRef
import requests
import time

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
CWE = Namespace("https://cwe.mitre.org/data/definitions/")
CPE = Namespace("http://example.org/cpe#")
CAPEC = Namespace("https://capec.mitre.org/data/definitions/")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)
rdf_graph.bind("cwe", CWE)
rdf_graph.bind("cpe", CPE)
rdf_graph.bind("capec", CAPEC)

classes = [
    ("CVE", STUCO.Vulnerability), ("CWE", STUCO.Weakness), ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity), ("CAPEC", CYBER.CAPEC), ("Vendor", CYBER.Vendor),
    ("Product", CYBER.Product), ("Version", CYBER.Version), ("Patch", CYBER.Patch)
]
for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. API NVD ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 6. UTILS ========================
def parse_cpe(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5] if len(parts) > 5 else "unknown"
        }
    except:
        return {}

# ======================== 7. INSERTION ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")

    existing_node = graph.nodes.match("CVE", name=cve_id).first()
    if existing_node:
        if existing_node.get("description") == description:
            print(f"⏭️ {cve_id} déjà présent et inchangé.")
            return

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published:
        cve_node["published"] = published

    # RDF CVE
    rdf_cve = URIRef(f"http://example.org/cve/{cve_id}")
    rdf_graph.add((rdf_cve, RDF.type, STUCO.Vulnerability))
    rdf_graph.add((rdf_cve, RDFS.label, Literal(cve_id)))
    rdf_graph.add((rdf_cve, RDFS.comment, Literal(description)))

    # CVSS metrics
    try:
        metrics = item["cve"].get("metrics", {})
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

    # CWE
    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                cwe_node = graph.nodes.match("CWE", name=cwe_id).first()
                if not cwe_node:
                    cwe_node = Node("CWE", name=cwe_id)
                    graph.create(cwe_node)

                cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
                cwe_node["url"] = cwe_url
                cwe_node["label"] = desc.get("description", "N/A")
                graph.push(cwe_node)

                graph.merge(Relationship(cve_node, "ASSOCIATED_WITH", cwe_node))

                # RDF CWE
                rdf_cwe = URIRef(cwe_url)
                rdf_graph.add((rdf_cwe, RDF.type, STUCO.Weakness))
                rdf_graph.add((rdf_cwe, RDFS.label, Literal(cwe_id)))
                rdf_graph.add((rdf_cwe, RDFS.comment, Literal(desc.get("description", ""))))
                rdf_graph.add((rdf_cve, CYBER.associatedWith, rdf_cwe))

    # CPE
    try:
        nodes = item["cve"].get("configurations", [{}])[0].get("nodes", [])
        for config in nodes:
            for cpe in config.get("cpeMatch", []):
                cpe_uri = cpe["criteria"]
                cpe_node = Node("CPE", name=cpe_uri)
                graph.merge(cpe_node, "CPE", "name")
                graph.merge(Relationship(cve_node, "AFFECTS", cpe_node))

                parsed = parse_cpe(cpe_uri)
                vendor_node = Node("Vendor", name=parsed["vendor"])
                product_node = Node("Product", name=parsed["product"])
                version_node = Node("Version", name=parsed["version"])

                graph.merge(vendor_node, "Vendor", "name")
                graph.merge(product_node, "Product", "name")
                graph.merge(version_node, "Version", "name")

                graph.merge(Relationship(product_node, "has_version", version_node))
                graph.merge(Relationship(product_node, "published_by", vendor_node))
                graph.merge(Relationship(cpe_node, "identifies", product_node))

                # RDF CPE
                rdf_cpe = URIRef(f"http://example.org/cpe#{cpe_uri}")
                rdf_graph.add((rdf_cpe, RDF.type, STUCO.Platform))
                rdf_graph.add((rdf_cpe, RDFS.label, Literal(cpe_uri)))
                rdf_graph.add((rdf_cve, CYBER.affects, rdf_cpe))
    except:
        pass

    # CAPEC
    try:
        for ref in item["cve"].get("references", []):
            url = ref.get("url", "")
            if "CAPEC-" in url:
                capec_id = "CAPEC-" + url.split("CAPEC-")[-1].split(".")[0]
                capec_node = Node("CAPEC", name=capec_id)
                graph.merge(capec_node, "CAPEC", "name")
                graph.merge(Relationship(cve_node, "has_CAPEC", capec_node))

                capec_url = f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html"
                rdf_capec = URIRef(capec_url)
                rdf_graph.add((rdf_capec, RDF.type, CYBER.CAPEC))
                rdf_graph.add((rdf_capec, RDFS.label, Literal(capec_id)))
                rdf_graph.add((rdf_cve, CYBER.hasCAPEC, rdf_capec))
    except:
        pass

    # Entités NER
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

# ======================== 8. PIPELINE ========================
def pipeline_kg1(start=0, results_per_page=10):
    print("🚀 Extraction CVE depuis NVD...")
    data = fetch_cve_nvd(start=start, results_per_page=results_per_page)
    for item in data.get("vulnerabilities", []):
        try:
            insert_cve_neo4j(item)
            time.sleep(0.2)
        except Exception as e:
            print(f"[!] Erreur {item['cve']['id']}: {e}")
    rdf_graph.serialize(destination="kg1.ttl", format="turtle")
    print("✅ KG1 inséré dans Neo4j et kg1.ttl mis à jour.")

# ======================== 9. EXÉCUTION ========================
if __name__ == "__main__":
    pipeline_kg1(start=0, results_per_page=2000)
               
