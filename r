import json
import matplotlib.pyplot as plt
from collections import Counter

# 1. Chargement des données
with open('threat-actor-cleaned.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 2. Extraction des années (on ignore les "Unknown")
years = []
for actor in data:
    year = actor.get('year_created')
    if year and year != "Unknown":
        # On s'assure que c'est bien un chiffre (ex: "2014")
        years.append(int(year))

# 3. Comptage par année
year_counts = Counter(years)
sorted_years = sorted(year_counts.items()) # Tri par ordre chronologique

x_years = [y[0] for y in sorted_years]
y_counts = [y[1] for y in sorted_years]

# 4. Création du graphique
plt.figure(figsize=(12, 6))
plt.plot(x_years, y_counts, marker='o', linestyle='-', color='#1f77b4', linewidth=2)
plt.fill_between(x_years, y_counts, alpha=0.2, color='#1f77b4')

plt.title("Évolution de l'apparition des nouveaux acteurs de menace (Cyberia)", fontsize=14)
plt.xlabel("Année de première apparition", fontsize=12)
plt.ylabel("Nombre de nouveaux groupes détectés", fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# Affichage des étiquettes pour chaque point
for i, count in enumerate(y_counts):
    plt.annotate(str(count), (x_years[i], y_counts[i]), textcoords="offset points", xytext=(0,10), ha='center')

plt.tight_layout()
plt.savefig('analyse_temporelle_cyberia.png')
print("✅ Graphique sauvegardé sous 'analyse_temporelle_cyberia.png'")
plt.show()