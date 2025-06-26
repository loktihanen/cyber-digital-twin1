# ======================== 1. IMPORTS ========================
from py2neo import Graph, Relationship
from fuzzywuzzy import fuzz
from sentence_transformers import SentenceTransformer, util
import os
# ======================== 2. CONNEXION NEO4J ======================
# Connexion Neo4j Aura Free avec paramètres codés en dur

from py2neo import Graph

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


# ======================== 3. INIT EMBEDDING MODEL ========================
model = SentenceTransformer("all-MiniLM-L6-v2")

# ======================== 4. ALIGNEMENT DES CVE ========================
def align_cve_nodes():
    print("🔎 Chargement des CVEs...")
    cve_nvd = list(graph.nodes.match("CVE").where("_.source = 'NVD'"))
    cve_nessus = list(graph.nodes.match("CVE").where("_.source = 'Nessus'"))

    print(f"📄 {len(cve_nvd)} CVEs NVD - {len(cve_nessus)} CVEs Nessus")

    count_exact, count_fuzzy, count_embed = 0, 0, 0

    # Indexation par nom pour match exact
    nvd_dict = {cve["name"]: cve for cve in cve_nvd}

    for nessus_cve in cve_nessus:
        name = nessus_cve.get("name")
        if not name:
            continue

        # ✅ Match exact
        if name in nvd_dict:
            graph.merge(Relationship(nessus_cve, "SAME_AS", nvd_dict[name]))
            count_exact += 1
            continue

        # 🧠 Match fuzzy (si le nom est légèrement différent)
        best_match = None
        best_score = 0
        for nvd_name in nvd_dict.keys():
            score = fuzz.ratio(name, nvd_name)
            if score > best_score:
                best_score = score
                best_match = nvd_dict[nvd_name]

        if best_score > 90:
            graph.merge(Relationship(nessus_cve, "SAME_AS", best_match))
            count_fuzzy += 1
            continue

        # 🧠 Match par embedding (si descriptions disponibles)
        desc1 = nessus_cve.get("description", "")
        desc2 = best_match.get("description", "") if best_match else ""
        if desc1 and desc2:
            emb1 = model.encode(desc1, convert_to_tensor=True)
            emb2 = model.encode(desc2, convert_to_tensor=True)
            sim = util.cos_sim(emb1, emb2).item()
            if sim > 0.85:
                graph.merge(Relationship(nessus_cve, "SAME_AS", best_match))
                count_embed += 1

    print(f"✅ Alignement terminé : {count_exact} exacts, {count_fuzzy} fuzzy, {count_embed} embeddings.")

# ======================== 5. EXECUTION ========================
if __name__ == "__main__":
    align_cve_nodes()

