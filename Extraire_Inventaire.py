import json
import os

# --- CONFIGURATION ---
input_file = 'threat-actor-cleaned.json'
output_folder = "Inventaire"

# Création automatique du dossier
os.makedirs(output_folder, exist_ok=True)

def extraire_inventaire():

    # 1. Chargement du JSON
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 2. Dictionnaire des catégories
    inventaire = {
        "noms_groupes": set(),
        "pays_sources": set(),
        "pays_attaques": set(),
        "outils": set(),
        "secteurs": set(),
        "types_incidents": set()
    }

    # 3. Fonction helper
    def ajouter_au_set(cle_inventaire, donnee):

        if not donnee:
            return

        if isinstance(donnee, list):
            for item in donnee:
                if item:
                    inventaire[cle_inventaire].add(str(item))

        else:
            inventaire[cle_inventaire].add(str(donnee))

    # 4. Parcours des données
    for entry in data:

        meta = entry.get('meta', {})

        ajouter_au_set("noms_groupes", entry.get('value'))
        ajouter_au_set("pays_sources", meta.get('cfr-suspected-state-sponsor'))
        ajouter_au_set("pays_attaques", meta.get('cfr-suspected-victims'))
        ajouter_au_set("outils", meta.get('cti_tools'))
        ajouter_au_set("secteurs", meta.get('cti_targets'))
        ajouter_au_set("types_incidents", meta.get('cfr-type-of-incident'))

    # 5. Affichage console
    print(f"\n{'VARIABLE':<25} | {'NB VALEURS UNIQUES'}")
    print("-" * 50)

    for cle, valeurs in inventaire.items():
        print(f"{cle:<25} | {len(valeurs)}")

    # 6. Sauvegarde d'un fichier séparé par catégorie
    for cle, valeurs in inventaire.items():

        nom_fichier = f"{cle}.txt"
        chemin_fichier = os.path.join(output_folder, nom_fichier)

        with open(chemin_fichier, 'w', encoding='utf-8') as f:

            valeurs_triees = sorted(list(valeurs))

            f.write(f"=== {cle.upper()} ===\n")
            f.write(f"Nombre de valeurs : {len(valeurs_triees)}\n\n")

            for valeur in valeurs_triees:
                f.write(valeur + "\n")

        print(f"✅ Fichier créé : {chemin_fichier}")

    return inventaire


# --- EXECUTION ---
mon_inventaire = extraire_inventaire()