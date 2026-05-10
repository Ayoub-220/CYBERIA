import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# --- CONFIGURATION ---
output_folder = "resultat"
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 1. Collecte des données
stats = {}
for entry in data:
    meta = entry.get('meta', {})
    sponsor = meta.get('cfr-suspected-state-sponsor')
    victims = meta.get('cfr-suspected-victims', [])
    
    if sponsor:
        stats[sponsor] = stats.get(sponsor, {'Lancees': 0, 'Subies': 0})
        stats[sponsor]['Lancees'] += 1
    
    for v in (victims if isinstance(victims, list) else [victims]):
        if v:
            stats[v] = stats.get(v, {'Lancees': 0, 'Subies': 0})
            stats[v]['Subies'] += 1

# 2. Préparation du DataFrame
df = pd.DataFrame.from_dict(stats, orient='index').reset_index()
df.columns = ['Pays', 'Lancees', 'Subies']

# On prend les 15 pays les plus actifs au total
df['Total_Activite'] = df['Lancees'] + df['Subies']
df_top = df.sort_values('Total_Activite', ascending=False).head(15)

# On transforme pour Seaborn (Format long)
df_plot = df_top.melt(id_vars='Pays', value_vars=['Lancees', 'Subies'], 
                      var_name='Type', value_name='Nombre')

# 3. Création du graphique (Grouped Bar Chart)
plt.figure(figsize=(12, 8))
sns.set_theme(style="white")

sns.barplot(data=df_plot, x='Nombre', y='Pays', hue='Type', palette=['#e74c3c', '#3498db'])

plt.title('Profil Géopolitique : Attaques Lancées (Rouge) vs Subies (Bleu)', fontsize=15, pad=20)
plt.xlabel('Nombre d\'événements enregistrés', fontsize=12)
plt.ylabel('', fontsize=12)
plt.legend(title='Rôle dans le conflit')

# 4. Sauvegarde
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "flux_agression_top15.png"), dpi=150)
plt.show()
