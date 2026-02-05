import json
import pandas as pd
import numpy as np

class ThreatActor_Cleaner:
    def __init__(self, json_file):
        """Initialise avec le chemin du JSON"""
        self.json_file = json_file
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
        self.save_cleaned_data()
        print("\n✅ Pipeline terminé!")


if __name__ == "__main__":
    
    cleaner = MyThreatActorCleaner('threat-actor.json')
    cleaner.run()