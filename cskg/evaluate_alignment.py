from py2neo import Graph

# Connexion à Neo4j Aura
graph = Graph("neo4j+s://8d5fbce8.databases.neo4j.io", auth=("neo4j", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"))

# 🔎 Nombre de relations SAME_AS réellement alignées
true_positives = graph.evaluate("MATCH (c1:CVE)-[:SAME_AS]->(c2:CVE) RETURN count(*)")
print(f"🔗 Relations SAME_AS détectées : {true_positives}")

# 📘 Nombre total de CVEs dans KG1 (NVD)
kg1_total = graph.evaluate("MATCH (c:CVE) WHERE c.source = 'NVD' RETURN count(*)")
# 📗 Nombre total de CVEs dans KG2 (Nessus)
kg2_total = graph.evaluate("MATCH (c:CVE) WHERE c.source = 'Nessus' RETURN count(*)")

# 🎯 Potentiel de correspondance (CVEs présents dans les deux graphes)
potential_matches = min(kg1_total, kg2_total)

# 🔁 Estimation du nombre d’alignements possibles (gold standard idéal)
gold_standard = potential_matches

# Précision : proportion d'alignements corrects parmi ceux trouvés
precision = true_positives / potential_matches if potential_matches else 0.0

# Rappel : proportion d'alignements trouvés parmi tous ceux attendus (supposés corrects)
recall = true_positives / gold_standard if gold_standard else 0.0

# F1-score : moyenne harmonique précision-rappel
f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

# Taux de couverture : alignements trouvés / total de KG2
coverage = true_positives / kg2_total if kg2_total else 0.0

# ======================== Résultats ========================
print("\n📊 Évaluation de l'alignement CVE KG1–KG2 :")
print(f"📘 CVEs dans KG1 (NVD) : {kg1_total}")
print(f"📗 CVEs dans KG2 (Nessus) : {kg2_total}")
print(f"🎯 Alignements attendus (gold standard estimé) : {gold_standard}")
print(f"✅ Alignements détectés (SAME_AS) : {true_positives}")
print(f"🔹 Précision        : {precision:.2%}")
print(f"🔹 Rappel           : {recall:.2%}")
print(f"🔹 F1-Score         : {f1_score:.2%}")
print(f"🔹 Taux de couverture : {coverage:.2%}")
