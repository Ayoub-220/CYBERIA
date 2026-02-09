import json
import pandas as pd
import numpy as np
import os
import re

class ThreatActor_Cleaner:
    def __init__(self, json_file, actors_file, tools_file):
        """Initialise avec le chemin du JSON"""
        self.json_file = json_file
        self.actors_file = actors_file
        self.tools_file = tools_file
        self.data = None
        self.data_clean = None 
        
    def load_data(self):
        """Charge le JSON et crée le DataFrame"""
        print("📂 Chargement des données...")
        
        with open(self.json_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)
            
        self.data_clean = self.data["values"]
        
        print(f"✅ {len(self.data_clean)} acteurs chargés")
        print(f"📊 Type: {type(self.data_clean)}")  # Liste
        
        # 
        print(f"\nPremier acteur:")
        print(f"  Nom: {self.data_clean[0]['value']}")
        print(f"  UUID: {self.data_clean[0]['uuid']}")

    
    def normalize_country_codes(self):
        """ÉTAPE 1: Normaliser les codes pays en MAJUSCULES"""
        print("\n🌍 ÉTAPE 1: Normalisation des codes pays...")
        
        #
        changes = 0
        
        # Parcourir tous les acteurs
        for actor in self.data_clean:
            # Vérifier si 'meta' existe
            if 'meta' in actor:
                # Vérifier si 'country' existe
                if 'country' in actor["meta"]:
                    country = actor["meta"]["country"]
                    country_upper = country.upper()
                    if country != country_upper:
                        actor['meta']['country'] = country_upper
                        changes += 1
        
        if changes == 0 :
            print("Aucun code pays normalisé")
        else :
            print(f"✅ {changes} codes pays normalisés")
    
    # Utile pour l'étape 2 !!!!!!!!!!!
    def analyze_sponsors(self):
        #Analyser tous les sponsors distincts
        print("\n🔍 ANALYSE: Liste des sponsors distincts...")
        
        sponsors = set() 
        
        for actor in self.data_clean:
            if 'meta' in actor:
                if 'cfr-suspected-state-sponsor' in actor['meta']:
                    sponsor = actor['meta']['cfr-suspected-state-sponsor']
                    sponsors.add(sponsor)
        
        # Trier par ordre alphabétique
        sponsors_sorted = sorted(sponsors)
        
        print(f"\n📊 {len(sponsors_sorted)} sponsors distincts trouvés:\n")
        for i, sponsor in enumerate(sponsors_sorted, 1):
            print(f"  {i:2d}. {sponsor}")
        
        return sponsors_sorted
        
    def add_short_sponsor_names(self):
        """ÉTAPE 2: Ajouter des noms courts pour les états suspectés"""
        print("\n🏛️  ÉTAPE 2: Ajout de noms courts pour les états suspectés...")
        
        changes = 0
        # Mapping basé sur l'analyse réelle des données de threat-actor-json grâce à la méthode (analyze_sponsor)
        sponsor_short = {
            # Noms long -> Nom court / cohérent pour 
            "People's Republic of China": "China",
            "US": "United States",
            "Russian Federation": "Russia",
            "Korea (Democratic People's Republic of)": "North Korea",
            "Korea (Republic of)": "South Korea",
            "Iran (Islamic Republic of)": "Iran",
        }
        
        for actor in self.data_clean:
            if "meta" in actor :
                if "cfr-suspected-state-sponsor" in actor["meta"]:
                    sponsor = actor["meta"]["cfr-suspected-state-sponsor"]
                    
                    if sponsor in sponsor_short :
                        actor["meta"]["cfr-suspected-state-sponsor"] = sponsor_short[sponsor]
                    changes += 1
                        
        if changes == 0 :
            print("Aucun nom raccourci")
        else :
            print(f"✅ {changes} noms raccourcis")
            
    def remove_duplicates_in_lists(self):
        """ÉTAPE 3: Supprimer les doublons et identifier les champs concernés"""
        print("\n🗑️ ÉTAPE 3: Suppression des doublons...")
        
        total_removed = 0
        impacted_fields = [] # Pour stocker le nom des listes modifiées
            
        for actor in self.data_clean:
            if 'meta' not in actor:
                continue
                
            for key, values in actor['meta'].items():
                if isinstance(values, list):
                    original_count = len(values)
                    
                    unique_values = []
                    for item in values:
                        if item not in unique_values:
                            unique_values.append(item)
                    
                    # Si la taille a changé, on note la clé et on compte
                    if len(unique_values) < original_count:
                        impacted_fields.append(actor['meta'][key]) # Stocker la liste impactée
                        actor['meta'][key] = unique_values
                        total_removed += (original_count - len(unique_values))
                        
        
        if total_removed == 0:
            print("Aucun doublon supprimé.")
        else:
            print(f"✅ {total_removed} doublons supprimés.")
            print(f"🛠️ Listes impactées : ")
            for i, field in enumerate(impacted_fields, 1):
                print(f"             {i} - {field}")
            
    
    def simplify(self, text):
        """Normalise les noms pour le mapping (ex: 'APT-1' -> 'APT1')"""
        if not text: return ""
        return str(text).upper().replace("-", "").replace(" ", "").strip()
    
    def extract_mitre_ids(self, refs):
        """Extrait les IDs MITRE (Txxxx, Sxxxx, Gxxxx) depuis une liste d'URLs"""
        mitre_ids = []
        if not refs: return mitre_ids
        
        # Regex pour capturer les codes T, S ou G suivis de chiffres (ex: T1059 ou S0020)
        pattern = r'(T\d{4}(?:\.\d{3})?|S\d{4}|G\d{4})'
        
        for url in refs:
            matches = re.findall(pattern, str(url))
            for m in matches:
                mitre_ids.append(m)
        return list(set(mitre_ids)) # Unicité
    
    def enrich_all(self):
        """ÉTAPE 4: Enrichissement ThaiCERT + MITRE ATT&CK (Extraction via URLs)"""
        print("\n📊 ÉTAPE 4: Enrichissement ThaiCERT + MITRE ATT&CK...")
        
        if not os.path.exists(self.actors_file) or not os.path.exists(self.tools_file):
            print("❌ Fichiers TGC manquants.")
            return

        with open(self.actors_file, 'r', encoding='utf-8') as f:
            actors_list = json.load(f)["values"]
        with open(self.tools_file, 'r', encoding='utf-8') as f:
            tools_list = json.load(f)["values"]

        # 1. Map des Acteurs TGC + Extraction MITRE depuis leurs propres refs
        actors_map = {}
        for entry in actors_list:
            meta = entry.get("meta", {})
            # On extrait les IDs MITRE depuis les liens de l'acteur
            initial_mitre = self.extract_mitre_ids(meta.get("refs", []))
            
            info = {
                "uuid": entry.get("uuid"),
                "motivation": meta.get("motivation", []),
                "targets": meta.get("cfr-target-category", []),
                "tools": [],
                "mitre_techniques": initial_mitre 
            }
            actors_map[self.simplify(entry.get("value"))] = info
            for syn in meta.get("synonyms", []):
                actors_map[self.simplify(syn)] = info

        # 2. Map des Outils + Extraction MITRE depuis les refs des outils
        for tool in tools_list:
            tool_name = tool.get("value")
            tool_meta = tool.get("meta", {})
            # On extrait les IDs MITRE depuis les liens de l'outil
            tool_mitre_ids = self.extract_mitre_ids(tool_meta.get("refs", []))
            # On ajoute aussi les IDs s'ils sont déjà présents dans le champ 'mitre-attack'
            tool_mitre_ids.extend(tool_meta.get("mitre-attack", []))
            
            for rel in tool.get("related", []):
                if rel.get("type") == "used-by":
                    dest_uuid = rel.get("dest-uuid")
                    for act_info in actors_map.values():
                        if act_info["uuid"] == dest_uuid:
                            act_info["tools"].append(tool_name)
                            act_info["mitre_techniques"].extend(tool_mitre_ids)

        # 3. Application finale au jeu de données source
        match_count = 0
        for actor in self.data_clean:
            key = self.simplify(actor.get("value"))
            if key in actors_map:
                match = actors_map[key]
                if "meta" not in actor: actor["meta"] = {}
                
                actor["meta"]["cti_motivation"] = match["motivation"]
                actor["meta"]["cti_targets"] = match["targets"]
                actor["meta"]["cti_tools"] = list(set(match["tools"]))
                # On nettoie la liste MITRE finale pour éviter les doublons
                actor["meta"]["mitre_techniques"] = list(set(match["mitre_techniques"]))
                match_count += 1

        print(f"✅ {match_count} acteurs enrichis avec succès (Données + MITRE).")
    
    
    
    
    
    def save_cleaned_data(self, output_file='threat-actor-cleaned.json'):
        """Sauvegarde les données nettoyées en JSON"""
        print(f"\n💾 Sauvegarde des données vers {output_file}...")
        
        output_data = self.data_clean.copy()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ {len(self.data_clean)} acteurs sauvegardés!")
        
    #  
    def run(self):
        """Pipeline"""
        self.load_data()
        self.normalize_country_codes()
        #self.analyze_sponsors()
        self.add_short_sponsor_names()
        self.remove_duplicates_in_lists()
        self.enrich_all()
        self.save_cleaned_data()
        print("\n✅ Pipeline terminé!")


if __name__ == "__main__":
    cleaner = ThreatActor_Cleaner('threat-actor.json', 'tgc-actors.json', 'tgc-tools.json')
    cleaner.run()