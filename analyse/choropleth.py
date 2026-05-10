import json
import pandas as pd
import plotly.graph_objects as go
from collections import defaultdict

# 1. CHARGEMENT
with open('threat-actor-cleaned.json', encoding='utf-8') as f:
    data = json.load(f)

# 2. AGRÉGATION PAR PAYS 
country_data = defaultdict(lambda: {
    'count': 0, 'gmi': None, 'regime': None, 'iso2': None
})

for actor in data:
    meta = actor.get('meta', {})
    sponsor = meta.get('cfr-suspected-state-sponsor')
    if not sponsor or sponsor == 'Unknown':
        continue
    country_data[sponsor]['count'] += 1
    if meta.get('gmi_score'):
        country_data[sponsor]['gmi'] = meta['gmi_score']
    if meta.get('political_regime_label'):
        country_data[sponsor]['regime'] = meta['political_regime_label']
    if meta.get('country'):
        country_data[sponsor]['iso2'] = meta['country']

# 3. DATAFRAME 
rows = []
for country, info in country_data.items():
    rows.append({
        'Pays': country,
        'ISO2': info['iso2'],
        'Acteurs': info['count'],
        'GMI': info['gmi'] if info['gmi'] else 0,
        'Regime': info['regime'] if info['regime'] else 'Unknown',
    })

df = pd.DataFrame(rows).sort_values('Acteurs', ascending=False)

# Mapping ISO2 → ISO3 pour Plotly
iso2_to_iso3 = {
    'CN': 'CHN', 'RU': 'RUS', 'IR': 'IRN', 'US': 'USA', 'KP': 'PRK',
    'KR': 'KOR', 'PK': 'PAK', 'IN': 'IND', 'BY': 'BLR', 'FR': 'FRA',
    'AE': 'ARE', 'VN': 'VNM', 'ES': 'ESP', 'IL': 'ISR', 'LB': 'LBN',
    'PS': 'PSE',
}
df['ISO3'] = df['ISO2'].map(iso2_to_iso3)
df = df.dropna(subset=['ISO3'])

# Couleur par régime
regime_colors = {
    'Closed Autocracy':    '#C0392B',
    'Electoral Autocracy': '#E67E22',
    'Electoral Democracy': '#2980B9',
    'Liberal Democracy':   '#27AE60',
    'Unknown':             '#7F8C8D',
}
df['Color'] = df['Regime'].map(regime_colors).fillna('#7F8C8D')

# ── 4. CARTE ──────────────────────────────────────────────────────────────────
BG = '#0F1923'

# Hover text
df['hover'] = df.apply(lambda r: (
    f"<b>{r['Pays']}</b><br>"
    f"Acteurs : {r['Acteurs']}<br>"
    f"Régime : {r['Regime']}<br>"
    f"Score GMI : {int(r['GMI']) if r['GMI'] else 'N/A'}"
), axis=1)

fig = go.Figure()

# Fond de carte gris pour tous les pays
fig.add_trace(go.Choropleth(
    locations=df['ISO3'],
    z=df['Acteurs'],
    colorscale=[
        [0.0,  '#1A2535'],
        [0.05, '#1C3A5E'],
        [0.15, '#1F5C8B'],
        [0.35, '#E67E22'],
        [0.65, '#E74C3C'],
        [1.0,  '#8B0000'],
    ],
    zmin=0,
    zmax=df['Acteurs'].max(),
    marker_line_color='#2C3E50',
    marker_line_width=0.8,
    colorbar=dict(
        title=dict(text='Nb acteurs', font=dict(color='white', size=12)),
        tickfont=dict(color='white'),
        bgcolor='rgba(15,25,35,0.8)',
        bordercolor='#2C3E50',
        x=1.01,
        thickness=15,
    ),
    text=df['hover'],
    hovertemplate='%{text}<extra></extra>',
    name='',
))

# Points proportionnels au GMI
df_gmi = df[df['GMI'] > 0].copy()
fig.add_trace(go.Scattergeo(
    locations=df_gmi['ISO3'],
    mode='markers',
    marker=dict(
        size=df_gmi['GMI'] / 10,
        color=df_gmi['Color'],
        opacity=0.85,
        line=dict(color='white', width=0.8),
    ),
    text=df_gmi['hover'],
    hovertemplate='%{text}<extra></extra>',
    name='Score GMI',
))

# ── 5. LÉGENDE RÉGIMES ────────────────────────────────────────────────────────
for regime, color in regime_colors.items():
    if regime == 'Unknown':
        continue
    fig.add_trace(go.Scattergeo(
        lon=[None], lat=[None],
        mode='markers',
        marker=dict(size=10, color=color),
        name=regime,
        showlegend=True,
    ))

# ── 6. LAYOUT ─────────────────────────────────────────────────────────────────
fig.update_layout(
    title=dict(
        text='CYBERIA — Cartographie mondiale des acteurs cybercriminels étatiques',
        font=dict(color='white', size=16, family='Arial'),
        x=0.5,
        xanchor='center',
        y=0.97,
    ),
    paper_bgcolor=BG,
    plot_bgcolor=BG,
    geo=dict(
        showframe=False,
        showcoastlines=True,
        coastlinecolor='#2C3E50',
        showland=True,
        landcolor='#1A2535',
        showocean=True,
        oceancolor='#0D1520',
        showlakes=False,
        showcountries=True,
        countrycolor='#2C3E50',
        bgcolor=BG,
        projection_type='natural earth',
    ),
    legend=dict(
        title=dict(text='Régime politique', font=dict(color='white', size=11)),
        font=dict(color='white', size=10),
        bgcolor='rgba(15,25,35,0.85)',
        bordercolor='#2C3E50',
        borderwidth=1,
        x=0.01,
        y=0.35,
    ),
    annotations=[
        dict(
            text=(
                '<b>Intensité de couleur</b> : nombre d\'acteurs sponsorisés  '
                '|  <b>Taille des cercles</b> : Score GMI (militarisation)  '
                '|  <b>Couleur des cercles</b> : régime politique'
            ),
            xref='paper', yref='paper',
            x=0.5, y=-0.02,
            xanchor='center',
            font=dict(color='#AAAAAA', size=10),
            showarrow=False,
        )
    ],
    margin=dict(l=0, r=0, t=50, b=40),
    width=1300,
    height=700,
)

# ── 7. EXPORT ─────────────────────────────────────────────────────────────────
fig.write_html('html/choropleth_mondiale.html')
print('✅ Carte sauvegardée : html/choropleth_mondiale.html')
fig.show()
