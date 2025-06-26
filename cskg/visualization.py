# ======================== 1. IMPORTS ========================
from py2neo import Graph
from pyvis.network import Network
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

# ======================== 3. VISUALISATION PRINCIPALE ========================
def visualize_graph(output_file="graph.html"):
    net = Network(height="800px", width="100%", directed=True, notebook=False)
    net.force_atlas_2based()

    query = """
    MATCH (a)-[r]->(b)
    WHERE a.name IS NOT NULL AND b.name IS NOT NULL
    RETURN DISTINCT labels(a)[0] AS source_type, a.name AS source,
                    type(r) AS relation,
                    labels(b)[0] AS target_type, b.name AS target,
                    r.score AS score
    LIMIT 1000
    """
    data = graph.run(query).data()

    nodes_set = set()
    for row in data:
        src, dst = row["source"], row["target"]
        rel = row["relation"]
        score = row.get("score", "")
        src_type = row["source_type"]
        dst_type = row["target_type"]

        if src not in nodes_set:
            net.add_node(src, label=src, title=src_type, color=node_color(src_type))
            nodes_set.add(src)
        if dst not in nodes_set:
            net.add_node(dst, label=dst, title=dst_type, color=node_color(dst_type))
            nodes_set.add(dst)

        label = rel
        if score:
            label += f" ({score})"
        net.add_edge(src, dst, label=label)

    net.show(output_file)
    print(f"✅ Graphe exporté dans {output_file}")

# ======================== 4. COULEUR PAR TYPE ========================
def node_color(node_type):
    colors = {
        "CVE": "#ff6666",
        "CVE_UNIFIED": "#cc0000",
        "CWE": "#ffcc00",
        "CPE": "#ff9900",
        "Plugin": "#66b3ff",
        "Host": "#0099cc",
        "Port": "#00cccc",
        "Service": "#33cc33",
        "Entity": "#999999"
    }
    return colors.get(node_type, "#dddddd")

# ======================== 5. MAIN ========================
if __name__ == "__main__":
    os.makedirs("data/visuals", exist_ok=True)
    visualize_graph(output_file="data/graph.html")
