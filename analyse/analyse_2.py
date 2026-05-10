import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# 1. Configuration du dossier et chargement
output_folder = "resultat"
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

rows = []
for entry in data:
    meta = entry.get('meta', {})
    tools = meta.get('cti_tools', [])
    sectors = meta.get('cti_targets', [])
    
    # Nettoyage et normalisation
    if isinstance(tools, str): tools = [tools]
    if isinstance(sectors, str): sectors = [sectors]
    tools = [t for t in tools if t]
    sectors = [s for s in sectors if s]
    
    if tools and sectors:
        rows.append({'Nb_Outils': len(tools), 'Secteurs': sectors})

# 2. Traitement des données
df = pd.DataFrame(rows).explode('Secteurs')
sector_stats = df.groupby('Secteurs')['Nb_Outils'].agg(['mean', 'count']).reset_index()
sector_stats.columns = ['Secteur', 'Complexite', 'Nombre_Acteurs']

# Filtre : secteurs significatifs (>5 acteurs) triés par complexité
sector_stats = sector_stats[sector_stats['Nombre_Acteurs'] > 5].sort_values('Complexite', ascending=False)

# 3. Création du graphique PNG avec Seaborn
plt.figure(figsize=(12, 8))
sns.set_theme(style="whitegrid")

# Barplot : X = Secteur, Y = Complexité
plot = sns.barplot(
    data=sector_stats.head(20), 
    x='Complexite', 
    y='Secteur', 
    palette='flare'
)

plt.title('Complexité de l\'Arsenal Cyber par Secteur d\'Activité', fontsize=15)
plt.xlabel('Nombre moyen d\'outils par groupe d\'attaque', fontsize=12)
plt.ylabel('Secteur Cible', fontsize=12)

# 4. Sauvegarde et affichage
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "complexite_secteurs.png"))
plt.show()