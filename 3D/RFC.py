import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

# 1. Chargement des données
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 2. Transformation des données pour la 3D
rows = []
for entry in data:
    meta = entry.get('meta', {})

    # Calcul de la Complexité : on compte le nombre de techniques MITRE
    techniques = meta.get('mitre_techniques', [])
    complexity = len(techniques) if isinstance(techniques, list) else 0

    row = {
        'Nom': entry.get('value'),
        'Pays': meta.get('cfr-suspected-state-sponsor', 'Inconnu'),
        'Regime_Label': meta.get('political_regime_label', 'Inconnu'),
        'Regime_Code': meta.get('political_regime_code'),
        'Force_GMI': meta.get('gmi_score'),
        'Complexite': complexity,
        'Annee': entry.get('year_created'),
        'Techniques_Count': complexity
    }
    rows.append(row)

# 3. Création du DataFrame
df = pd.DataFrame(rows)
df_plot = df.dropna(subset=['Force_GMI', 'Regime_Code']).copy()

print(f"Total d'acteurs analysés: {len(df_plot)}")
print(f"Régimes politiques trouvés: {df_plot['Regime_Label'].unique()}")
print(f"\nStatistiques:")
print(f"  - Force GMI: min={df_plot['Force_GMI'].min():.1f}, max={df_plot['Force_GMI'].max():.1f}")
print(f"  - Complexité: min={df_plot['Complexite'].min()}, max={df_plot['Complexite'].max()}")

# 5. Visualisation 3D enrichie
fig = px.scatter_3d(
    df_plot,
    x='Regime_Code',
    y='Force_GMI',
    z='Complexite',
    color='Regime_Label',
    size='Force_GMI',
    size_max=20,
    opacity=0.8,
    hover_name='Nom',
    hover_data={
        'Pays': True,
        'Annee': True,
        'Regime_Code': ':.0f',
        'Force_GMI': ':.2f',
        'Complexite': True
    },
    title="Analyse 4D Cyberia : Régime Politique - Force Militaire - Complexité Cyber",
    labels={
        'Regime_Code': 'Régime Politique (0=Autocratie → 3=Démocratie)',
        'Force_GMI': 'Score de Militarisation (GMI)',
        'Complexite': 'Complexité Cyber (Techniques MITRE)'
    }
)

# Amélioration du layout
fig.update_layout(
    margin=dict(l=0, r=0, b=0, t=50),
    width=1200,
    height=800,
    font=dict(size=11),
    scene=dict(
        xaxis_title="Régime Politique",
        yaxis_title="Force GMI",
        zaxis_title="Techniques MITRE",
        camera=dict(
            eye=dict(x=1.5, y=1.5, z=1.3)
        )
    ),
    hovermode='closest'
)

# 6. Sauvegarde en HTML
output_file = 'html/visualization_3d.html'
fig.write_html(output_file)
print(f"\n✓ Visualisation sauvegardée: {output_file}")

fig.show()