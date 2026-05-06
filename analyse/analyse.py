import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

def generate_tactical_signatures(file_path):
    n = 20  # Nombre de top éléments à afficher pour la lisibilité (ne pas mettre trop haut pour éviter un graphique illisible)
    # 1. Chargement des données
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    tool_victim_pairs = []
    tool_sector_pairs = []

    # 2. Extraction des relations
    for entry in data:
        meta = entry.get('meta', {})
        tools = meta.get('cti_tools', [])
        victims = meta.get('cfr-suspected-victims', [])
        sectors = meta.get('cti_targets', []) # 'cti_targets' contient souvent les secteurs
        
        # S'assurer que ce sont des listes
        if isinstance(tools, str): tools = [tools]
        if isinstance(victims, str): victims = [victims]
        if isinstance(sectors, str): sectors = [sectors]
        
        for tool in tools:
            if not tool: continue
            for victim in victims:
                if victim: tool_victim_pairs.append({'Outil': tool, 'Pays_Cible': victim})
            for sector in sectors:
                if sector: tool_sector_pairs.append({'Outil': tool, 'Secteur': sector})

    # 3. Création des DataFrames
    df_victims = pd.DataFrame(tool_victim_pairs)
    df_sectors = pd.DataFrame(tool_sector_pairs)

    # 4. Filtrage pour la lisibilité (Top n)
    top_tools = df_victims['Outil'].value_counts().nlargest(n).index
    top_victims = df_victims['Pays_Cible'].value_counts().nlargest(n).index
    top_sectors = df_sectors['Secteur'].value_counts().nlargest(n).index

    # --- Visualisation 1 : Outils vs Pays Cibles ---
    plt.figure(figsize=(14, 10))
    pivot_v = df_victims[df_victims['Pays_Cible'].isin(top_victims) & 
                         df_victims['Outil'].isin(top_tools)].pivot_table(
                             index='Outil', columns='Pays_Cible', aggfunc='size', fill_value=0
                         )
    sns.heatmap(pivot_v, annot=True, cmap='YlGnBu', fmt='d')
    plt.title(f"Corrélation : Outils d\'Attaque vs Pays Cibles (Top {n})")
    plt.tight_layout()
    plt.savefig('resultat/analyse_outils_pays.png')
    plt.show()

    # --- Visualisation 2 : Outils vs Secteurs ---
    plt.figure(figsize=(14, 10))
    pivot_s = df_sectors[df_sectors['Secteur'].isin(top_sectors) & 
                         df_sectors['Outil'].isin(top_tools)].pivot_table(
                             index='Outil', columns='Secteur', aggfunc='size', fill_value=0
                         )
    sns.heatmap(pivot_s, annot=True, cmap='OrRd', fmt='d')
    plt.title(f"Corrélation : Outils d\'Attaque vs Secteurs d\'Activité (Top {n})")
    plt.tight_layout()
    plt.savefig('resultat/analyse_outils_secteurs.png')
    plt.show()
    
    print("✅ Les graphiques ont été générés et sauvegardés en images.")

# Lancement
if __name__ == "__main__":
    generate_tactical_signatures('threat-actor-cleaned.json')