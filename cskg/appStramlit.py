# app.py
import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

st.set_page_config(page_title="CSKG Dashboard", layout="wide")

# ========== SIDEBAR MENU ==========
menu = st.sidebar.radio("📌 Menu", [
    "CSKG1 – NVD",
    "CSKG2 – Nessus",
    "CSKG3 – Fusionné",
    "Simulation",
    "Recommandation",
    "Heatmap"
])

# ========== CSKG1 – NVD ==========
if menu == "CSKG1 – NVD":
    st.title("🧠 CSKG1 – Graphe de connaissances NVD")
    st.info("Affichage du graphe de connaissances basé sur les vulnérabilités connues issues de la base NVD.")
    
    # --- Extrait de données simulées
    df = pd.DataFrame({
        "CVE": ["CVE-2024-1234", "CVE-2024-5678"],
        "Produit": ["Apache", "OpenSSL"],
        "Score": [9.8, 7.5]
    })
    st.dataframe(df)

    # --- Exemple simple de visualisation graphe
    G = nx.Graph()
    G.add_edges_from([("Apache", "CVE-2024-1234"), ("OpenSSL", "CVE-2024-5678")])
    net = Network(notebook=False, height="400px", width="100%")
    net.from_nx(G)
    net.save_graph("cskg1.html")
    with open("cskg1.html", 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=450)

# ========== CSKG2 – Nessus ==========
elif menu == "CSKG2 – Nessus":
    st.title("🛡️ CSKG2 – Analyse Nessus")
    st.info("Visualisation des vulnérabilités extraites à partir des résultats de scan Nessus.")
    
    # Exemple de données Nessus simulées
    nessus_df = pd.DataFrame({
        "Host": ["host-01", "host-02"],
        "Vuln": ["CVE-2023-1000", "CVE-2024-8888"],
        "Severity": ["Critical", "High"]
    })
    st.dataframe(nessus_df)

    # Graphe simple
    G = nx.Graph()
    G.add_edges_from([("host-01", "CVE-2023-1000"), ("host-02", "CVE-2024-8888")])
    net = Network(notebook=False, height="400px", width="100%")
    net.from_nx(G)
    net.save_graph("cskg2.html")
    with open("cskg2.html", 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=450)

# ========== CSKG3 – Fusionné ==========
elif menu == "CSKG3 – Fusionné":
    st.title("🔀 CSKG3 – Graphe Fusionné (NVD + Nessus)")
    st.info("Représentation du graphe de connaissances fusionné incluant des relations SAME_AS et enrichissements.")

    # Exemple de graphe fusionné simulé
    G = nx.Graph()
    G.add_edges_from([
        ("host-01", "CVE-2024-1234"),
        ("host-01", "Apache"),
        ("CVE-2024-1234", "Apache"),
        ("CVE-2024-1234", "CVE-2024-9999", {"label": "SAME_AS"})
    ])
    net = Network(notebook=False, height="450px", width="100%")
    net.from_nx(G)
    net.save_graph("cskg3.html")
    with open("cskg3.html", 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=480)

# ========== Simulation ==========
elif menu == "Simulation":
    st.title("🧪 Simulation Cybersécurité (Digital Twin)")
    st.info("Expérimentation d’attaque simulée sur un réseau organisationnel.")
    
    # Exemple de simulation (valeurs fictives)
    hosts = ["host-01", "host-02", "host-03"]
    vuln_status = [True, False, True]
    df = pd.DataFrame({"Host": hosts, "Vulnerable": vuln_status})
    st.dataframe(df)

    # Diagramme de simulation
    fig, ax = plt.subplots()
    colors = ["red" if v else "green" for v in vuln_status]
    ax.bar(hosts, [1]*len(hosts), color=colors)
    ax.set_title("Statut des hôtes")
    st.pyplot(fig)

# ========== Recommandation ==========
elif menu == "Recommandation":
    st.title("🎯 Système de Recommandation")
    st.info("Recommandation d’actions correctives basées sur le graphe.")
    
    # Exemple de recommandation simple
    recs = {
        "host-01": "Mettre à jour Apache vers la version 2.4.58",
        "host-02": "Désactiver SSLv3"
    }
    st.json(recs)

# ========== Heatmap ==========
elif menu == "Heatmap":
    st.title("🔥 Heatmap des Vulnérabilités")
    st.info("Carte de chaleur représentant l’intensité des vulnérabilités par hôte.")

    # Données simulées
    data = np.random.rand(5, 5)
    hosts = [f"host-{i}" for i in range(1, 6)]
    vulns = [f"CVE-{2024+i}-000{i}" for i in range(5)]
    df = pd.DataFrame(data, index=hosts, columns=vulns)

    # Affichage heatmap
    fig, ax = plt.subplots(figsize=(8, 4))
    sns.heatmap(df, annot=True, cmap="Reds", cbar=True)
    st.pyplot(fig)
