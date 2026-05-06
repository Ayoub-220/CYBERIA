import json
import pandas as pd
import plotly.express as px

# 1. Chargement et préparation des données
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

rows = []
for entry in data:
    meta = entry.get('meta', {})
    techniques = meta.get('mitre_techniques', [])
    complexity = len(techniques) if isinstance(techniques, list) else 0
    
    rows.append({
        'Nom': entry.get('value'),
        'Pays': meta.get('cfr-suspected-state-sponsor', 'Inconnu'),
        'Regime': meta.get('political_regime_label', 'Inconnu'),
        'GDP': meta.get('attacker_gdp'), # Assure-toi que cette clé existe dans ton JSON
        'GMI': meta.get('gmi_score'),
        'Complexite': complexity
    })

df = pd.DataFrame(rows)

# Nettoyage des données manquantes pour le graph
df_plot = df.dropna(subset=['GDP', 'GMI', 'Complexite'])

# 2. Création de la visualisation 3D
fig = px.scatter_3d(
    df_plot, 
    x='GDP',            # Axe X : Richesse économique
    y='GMI',            # Axe Y : Priorité militaire
    z='Complexite',     # Axe Z : Diversité technique
    color='Regime',     # Couleur par type de régime pour voir si les blocs se détachent
    log_x=False,         # Échelle logarithmique pour le GDP (car les écarts sont énormes)
    hover_name='Nom',
    title="Le Triangle de la Puissance : Économie, Militarisation et Expertise Cyber",
    labels={
        'GDP': 'PIB (Richesse)',
        'GMI': 'Indice GMI (Militarisation)',
        'Complexite': 'Complexité (Nb Techniques)'
    }
)

fig.update_layout(scene = dict(
                    xaxis_title='PIB',
                    yaxis_title='Militarisation (GMI)',
                    zaxis_title='Complexité Cyber'))

fig.show()