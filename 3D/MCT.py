import json
import pandas as pd
import plotly.graph_objects as go
from collections import Counter
import numpy as np

# 1. Chargement et traitement des données
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

rows = []
motivation_counts = Counter()
target_counts = Counter()

for entry in data:
    meta = entry.get('meta', {})
    motivations = meta.get('cti_motivation', [])
    targets = meta.get('cti_targets', [])
    year = entry.get('year_created')

    # Extraire motivation principale
    main_motivation = None
    if motivations:
        main_motivation = motivations[0]
        motivation_counts[main_motivation] += 1

    # Compter les cibles
    for target in targets:
        target_counts[target] += 1

    row = {
        'Nom': entry.get('value'),
        'Motivations': motivations,
        'Main_Motivation': main_motivation or 'Unknown',
        'Targets': targets,
        'Targets_Count': len(targets),
        'Year': year,
        'Incident_Type': meta.get('cfr-type-of-incident')
    }
    rows.append(row)

df = pd.DataFrame(rows)

print("=" * 60)
print("SIGNATURE DE LA MOTIVATION - Analyse")
print("=" * 60)
print(f"\nTotal d'acteurs: {len(df)}")
print(f"\nMotivations principales (Top 5):")
for motivation, count in motivation_counts.most_common(5):
    print(f"  - {motivation}: {count} acteurs")

print(f"\nSecteurs cibles (Top 10):")
for target, count in target_counts.most_common(10):
    print(f"  - {target}: {count}")

# 2. Création du Radar Chart
fig = go.Figure()

# Données pour le radar
categories = ['Espionnage', 'Vol/Profit', 'Sabotage', 'Cyber-crime', 'Hacktivisme']
espionage_count = motivation_counts.get('Information theft and espionage', 0)
profit_count = sum(1 for m in motivation_counts if 'financial' in m.lower() or 'theft' in m.lower())
sabotage_count = sum(1 for m in motivation_counts if 'sabotage' in m.lower() or 'disruption' in m.lower())
crime_count = sum(1 for m in motivation_counts if 'crime' in m.lower())
activism_count = sum(1 for m in motivation_counts if 'activism' in m.lower() or 'hacktivis' in m.lower())

values = [espionage_count, profit_count, sabotage_count, crime_count, activism_count]
max_val = max(values) if values else 1

fig.add_trace(go.Scatterpolar(
    r=values,
    theta=categories,
    fill='toself',
    name='Motivation Distribution',
    line_color='#1f77b4',
    fillcolor='rgba(31, 119, 180, 0.3)'
))

fig.update_layout(
    polar=dict(
        radialaxis=dict(
            visible=True,
            range=[0, max_val * 1.1]
        )
    ),
    title="Signature de la Motivation - Distribution des Motivations Cyber",
    showlegend=True,
    font=dict(size=12),
    height=700,
    width=900
)

fig.write_html('html/motivation_radar.html')
print(f"\n✓ Radar chart sauvegardé: motivation_radar.html")

# 3. Visualisation 3D - Motivation vs Cibles vs Année
fig2 = go.Figure()

# Préparer les données pour le 3D scatter
df_3d = df[df['Targets_Count'] > 0].copy()
df_3d['Motivation_Score'] = df_3d['Main_Motivation'].map(motivation_counts)

# Mapper les motivations à des codes numériques
motivation_map = {
    'Information theft and espionage': 3,
    'Financial gain': 2,
    'Sabotage and disruption': 2.5,
    'Unknown': 1
}
df_3d['Motivation_Numeric'] = df_3d['Main_Motivation'].map(
    lambda x: motivation_map.get(x, 1.5)
)

fig2 = go.Figure(data=[go.Scatter3d(
    x=df_3d['Motivation_Numeric'],
    y=df_3d['Targets_Count'],
    z=df_3d['Year'],
    mode='markers',
    marker=dict(
        size=5,
        color=df_3d['Targets_Count'],
        colorscale='Viridis',
        showscale=True,
        colorbar=dict(title="Nb Cibles")
    ),
    text=df_3d['Nom'],
    hovertemplate='<b>%{text}</b><br>Motivations: %{customdata[0]}<br>Cibles: %{y}<br>Année: %{z}<extra></extra>',
    customdata=df_3d[['Main_Motivation']]
)])

fig2.update_layout(
    title="Signature 4D: Motivation - Cibles - Temporalité",
    scene=dict(
        xaxis_title="Motivation (1=Inconnue → 3=Espionnage)",
        yaxis_title="Nombre de Secteurs Cibles",
        zaxis_title="Année d'Apparition",
        camera=dict(eye=dict(x=1.5, y=1.5, z=1.3))
    ),
    width=1200,
    height=800,
    hovermode='closest'
)

fig2.write_html('html/motivation_signature_3d.html')
print(f"✓ Visualisation 3D sauvegardée: motivation_signature_3d.html\n")

fig.show()
fig2.show()
