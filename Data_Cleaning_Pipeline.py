import json
import requests
import pandas as pd
import numpy as np
import os
import re
from fuzzywuzzy import fuzz
from collections import defaultdict

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
    
    def extract_temporal_data(self):
        """Extraction de la chronologie avec gestion d'erreurs"""
        print("\n📅 ÉTAPE 5: Extraction des données temporelles...")
        changes = 0
        for actor in self.data_clean:
            # On récupère la date transmise par l'enrichissement
            created_date = actor.get('created')
            
            if created_date and isinstance(created_date, str):
                # On utilise une regex pour trouver les 4 chiffres de l'année 
                # (plus sûr que created_date[:4] si le format change)
                match = re.search(r'(\d{4})', created_date)
                if match:
                    actor['year_created'] = match.group(1)
                    changes += 1
                else:
                    actor['year_created'] = "Unknown"
            else:
                actor['year_created'] = "Unknown"
        
        print(f"✅ {changes} dates de création extraites sur les {len(self.data_clean)} acteurs.")
    
    def fuzzy_match_actor(self, name, candidates, threshold=85):
        """
        Trouve le meilleur match avec fuzzy matching
        
        Returns:
            (best_match_data, score, match_type, matched_name) ou (None, 0, None, None)
        """
        # 1. Essayer match exact d'abord
        name_simple = self.simplify(name)
        
        for candidate_name, data in candidates:
            if name_simple == self.simplify(candidate_name):
                return data, 100, 'exact', candidate_name  
        
        # 2. Fuzzy matching
        best_score = 0
        best_match = None
        best_candidate_name = None 
        for candidate_name, data in candidates:
            scores = [
                fuzz.ratio(name, candidate_name),
                fuzz.partial_ratio(name, candidate_name),
                fuzz.token_set_ratio(name, candidate_name),
            ]
            
            max_score = max(scores)
            
            if max_score > best_score:
                best_score = max_score
                best_match = data
                best_candidate_name = candidate_name 
        
        if best_score >= threshold:
            return best_match, best_score, 'fuzzy', best_candidate_name  
        
        return None, 0, None, None
    
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
        """ÉTAPE 4: Enrichissement ThaiCERT + MITRE ATT&CK avec Fuzzy Matching"""
        print("\n📊 ÉTAPE 4: Enrichissement ThaiCERT + MITRE ATT&CK...")
        
        if not os.path.exists(self.actors_file) or not os.path.exists(self.tools_file):
            print("❌ Fichiers TGC manquants.")
            return

        with open(self.actors_file, 'r', encoding='utf-8') as f:
            actors_list = json.load(f)["values"]
        with open(self.tools_file, 'r', encoding='utf-8') as f:
            tools_list = json.load(f)["values"]

    
        # ÉTAPE 1: Préparer les candidats TGC avec tous les noms possibles
    
        print("\n   📋 Préparation des candidats TGC...")
        tgc_candidates = []
        
        for entry in actors_list:
            # Nom principal
            main_name = entry.get("value")
            tgc_candidates.append((main_name, entry))
            
            # Synonymes
            for syn in entry.get("meta", {}).get("synonyms", []):
                tgc_candidates.append((syn, entry))
        
        print(f"   ✅ {len(tgc_candidates)} noms candidats créés (avec synonymes)")

    
        # ÉTAPE 2: Matcher chaque acteur avec fuzzy matching
    
        print(f"\n   🔍 Matching des acteurs avec fuzzy...")
        
        actors_map = {}
        exact_matches = 0
        fuzzy_matches = 0
        no_matches = 0
        
        for actor in self.data_clean:
            actor_name = actor.get("value")
            
            # Utiliser fuzzy matching
            match_data, score, match_type, matched_name = self.fuzzy_match_actor(
                actor_name, 
                tgc_candidates,
                threshold=95
            )
            
            if not match_data:
                no_matches += 1
                continue
            
            # Stats pour le matching
            if match_type == "exact":
                exact_matches += 1
            elif match_type == "fuzzy":
                fuzzy_matches += 1
                if fuzzy_matches == 1:
                    print(f"\n      {'Source':<30} {'Match TGC':<45} {'Score':>6}")
                    print(f"      {'-'*30} {'-'*45} {'-'*6}")
                print(f"      {actor_name:<30} {matched_name:<45} {score:>6}")
            
            # Extraire infos TGC
            meta = match_data.get("meta", {})
            initial_mitre = self.extract_mitre_ids(meta.get("refs", []))
            
            potential_date = meta.get("date")
            
            info = {
                "uuid": match_data.get("uuid"),
                "motivation": meta.get("motivation", []),
                "targets": meta.get("cfr-target-category", []),
                "tools": [],
                "mitre_techniques": initial_mitre,
                "created": str(potential_date) if potential_date else None
            }
            
            # Stocker dans actors_map avec la clé simplifiée
            key = self.simplify(actor_name)
            actors_map[key] = info
        
        print(f"\n   ✅ RÉSULTATS DU MATCHING:")
        print(f"      • Matches exacts:  {exact_matches}")
        print(f"      • Matches fuzzy:   {fuzzy_matches}")
        print(f"      • Non matchés:     {no_matches}")
        print(f"      • TOTAL enrichis:  {exact_matches + fuzzy_matches}/{len(self.data_clean)} ({(exact_matches + fuzzy_matches)/len(self.data_clean)*100:.1f}%)")

        # ÉTAPE 3: Enrichir avec les outils
        
        print(f"\n   🔧 Enrichissement avec les outils...")
        
        tools_added = 0
        
        for tool in tools_list:
            tool_name = tool.get("value")
            tool_meta = tool.get("meta", {})
            
            # Extraire les IDs MITRE depuis les liens de l'outil
            tool_mitre_ids = self.extract_mitre_ids(tool_meta.get("refs", []))
            # Ajouter aussi les IDs déjà présents dans 'mitre-attack'
            tool_mitre_ids.extend(tool_meta.get("mitre-attack", []))
            
            # Pour chaque relation "used-by"
            for rel in tool.get("related", []):
                if rel.get("type") == "used-by":
                    dest_uuid = rel.get("dest-uuid")
                    
                    # Trouver l'acteur correspondant dans actors_map
                    for act_info in actors_map.values():
                        if act_info["uuid"] == dest_uuid:
                            act_info["tools"].append(tool_name)
                            act_info["mitre_techniques"].extend(tool_mitre_ids)
                            tools_added += 1
        
        print(f"   ✅ {tools_added} relations outils ajoutées")

    
        # ÉTAPE 4: Application finale aux données
    
        print(f"\n   💾 Application des enrichissements...")
        
        final_enriched = 0
        
        for actor in self.data_clean:
            key = self.simplify(actor.get("value"))
            
            if key in actors_map:
                match = actors_map[key]
                if "meta" not in actor:
                    actor["meta"] = {}
                
                # Ajouter les données enrichies
                actor["meta"]["cti_motivation"] = match["motivation"]
                actor["meta"]["cti_targets"] = match["targets"]
                actor["meta"]["cti_tools"] = list(set(match["tools"]))
                # Nettoyer la liste MITRE finale pour éviter les doublons
                actor["meta"]["mitre_techniques"] = list(set(match["mitre_techniques"]))
                actor["created"] = match["created"]
                if final_enriched == 1:
                    print(f"   🔍 DEBUG : Exemple de date récupérée : {actor['created']}")
                
                if actor["created"]:
                    # print(f"DEBUG: Date trouvée pour {actor.get('value')}") 
                    pass
                
                final_enriched += 1
        
        print(f"   ✅ {final_enriched} acteurs enrichis avec succès")
        print(f"\n✅ Enrichissement terminé!")

    # ══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 6 — ENRICHISSEMENT MITRE ATT&CK ONLINE (depuis enrichissement.py)
    # Télécharge la base MITRE ATT&CK complète depuis GitHub et résout
    # chaque code mitre_techniques en nom lisible + tactiques ATT&CK.
    # Résultat stocké dans meta['mitre_techniques_resolved']
    # ══════════════════════════════════════════════════════════════════════════
    def fetch_mitre_mapping(self):
        """Télécharge la base MITRE ATT&CK (Techniques et Outils) depuis GitHub"""
        print("\n🌐 ÉTAPE 6 [1/2] Connexion à MITRE ATT&CK...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        mapping = {}
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for obj in data.get('objects', []):
                    if obj.get('type') in ['attack-pattern', 'malware', 'tool']:
                        for ref in obj.get('external_references', []):
                            if ref.get('source_name') == 'mitre-attack':
                                mitre_id = ref.get('external_id')
                                name = obj.get('name', 'Unknown')
                                # On récupère les phases de l'attaque (ex: Persistence)
                                phases = [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]
                                phase_str = f" [{', '.join(phases)}]" if phases else ""
                                mapping[mitre_id] = f"{name}{phase_str} ({mitre_id})"
                print(f"   ✅ {len(mapping)} définitions techniques chargées.")
            else:
                print(f"   ⚠️  Réponse inattendue : HTTP {response.status_code}")
        except Exception as e:
            print(f"   ❌ Erreur MITRE (pas de connexion ?) : {e}")
            print("   ℹ️  L'étape 6 sera ignorée, les autres étapes ne sont pas affectées.")
        return mapping

    # ══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 6 — ENRICHISSEMENT MISP GALAXY (depuis enrichissement.py)
    # Télécharge le cluster MISP threat-actor et indexe tous les noms +
    # synonymes pour retrouver first_seen / last_seen de chaque acteur.
    # Corrige aussi les year_created = 'Unknown' quand une date MISP existe.
    # ══════════════════════════════════════════════════════════════════════════
    def fetch_misp_galaxy(self):
        """Télécharge et indexe TOUS les noms (principaux + synonymes) de MISP"""
        print("\n🌐 ÉTAPE 6 [2/2] Connexion à MISP (Galaxies)...")
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        lookup = {}
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('values', []):
                    main_name = entry.get('value', '')
                    meta = entry.get('meta', {})
                    
                    info = {
                        'first_seen': meta.get('first_seen', 'Unknown'),
                        'last_seen':  meta.get('last_seen',  'Unknown'),
                        'main_name':  main_name
                    }
                    
                    # Indexation du nom principal
                    lookup[main_name.lower().strip()] = info
                    
                    # Indexation de tous les synonymes
                    synonyms = meta.get('synonyms', [])
                    if isinstance(synonyms, list):
                        for syn in synonyms:
                            lookup[syn.lower().strip()] = info
                
                print(f"   ✅ {len(lookup)} variantes de noms chargées via MISP.")
            else:
                print(f"   ⚠️  Réponse inattendue : HTTP {response.status_code}")
        except Exception as e:
            print(f"   ❌ Erreur MISP (pas de connexion ?) : {e}")
            print("   ℹ️  L'étape 6 sera ignorée, les autres étapes ne sont pas affectées.")
        return lookup

    def enrich_from_external_sources(self):
        """
        ÉTAPE 6: Enrichissement depuis des sources externes (MITRE ATT&CK + MISP)
        
        Apports :
          - mitre_techniques_resolved : codes MITRE résolus en noms lisibles + tactiques
          - first_seen_misp / last_seen_misp : dates d'activité depuis MISP Galaxy
          - misp_main_name : nom canonique MISP de l'acteur
          - year_created : corrigé si encore 'Unknown' et qu'une date MISP existe
        
        ⚠️  Nécessite une connexion internet. En cas d'échec réseau,
            l'étape est ignorée proprement sans bloquer le pipeline.
        """
        print("\n🔗 ÉTAPE 6: Enrichissement depuis sources externes (MITRE + MISP)...")

        # Récupération des deux sources
        mitre_map  = self.fetch_mitre_mapping()
        misp_lookup = self.fetch_misp_galaxy()

        # Si les deux échouent, on arrête proprement
        if not mitre_map and not misp_lookup:
            print("   ⚠️  Aucune source externe disponible — étape 6 ignorée.")
            return

        stats_dates   = 0   # year_created corrigés grâce à MISP
        stats_misp    = 0   # acteurs enrichis via MISP
        stats_mitre   = 0   # acteurs enrichis via MITRE

        for actor in self.data_clean:
            # ── Enrichissement MISP ───────────────────────────────────────────
            if misp_lookup:
                # Nettoyage pour comparaison : "Storm-1516" -> "storm-1516"
                name_key = actor['value'].lower().strip()
                misp_info = misp_lookup.get(name_key)

                if misp_info:
                    # Correction de year_created si encore inconnu
                    if actor.get('year_created') in ['Unknown', None, ""] \
                            and misp_info['first_seen'] != 'Unknown':
                        actor['year_created'] = str(misp_info['first_seen'])[:4]
                        stats_dates += 1

                    # Ajout des métadonnées MISP dans meta
                    actor['meta']['first_seen_misp'] = misp_info['first_seen']
                    actor['meta']['last_seen_misp']  = misp_info['last_seen']
                    actor['meta']['misp_main_name']  = misp_info['main_name']
                    stats_misp += 1

            # ── Enrichissement MITRE ──────────────────────────────────────────
            if mitre_map:
                tech_codes = actor.get('meta', {}).get('mitre_techniques', [])
                if tech_codes:
                    actor['meta']['mitre_techniques_resolved'] = [
                        mitre_map.get(str(c).strip(), c) for c in tech_codes
                    ]
                    stats_mitre += 1

        # Rapport final
        print(f"\n   📊 Résultats enrichissement externe :")
        print(f"      • Acteurs enrichis via MISP   : {stats_misp}")
        print(f"      • Dates 'Unknown' corrigées   : {stats_dates}")
        print(f"      • Acteurs enrichis via MITRE  : {stats_mitre}")
        print(f"\n✅ Enrichissement externe terminé!")

    def save_cleaned_data(self, output_file='threat-actor-cleaned.json'):
        """Sauvegarde les données nettoyées en JSON"""
        print(f"\n💾 Sauvegarde des données vers {output_file}...")
        
        output_data = self.data_clean.copy()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ {len(self.data_clean)} acteurs sauvegardés!")
        
          
    def run(self):
        """Pipeline complet"""
        self.load_data()
        self.normalize_country_codes()
        #self.analyze_sponsors()
        self.add_short_sponsor_names()
        self.remove_duplicates_in_lists()
        self.enrich_all()
        self.extract_temporal_data()
        self.enrich_from_external_sources()   # ← NOUVEAU : MITRE online + MISP
        self.save_cleaned_data()
        print("\n✅ Pipeline terminé!")

if __name__ == "__main__":
    cleaner = ThreatActor_Cleaner('threat-actor.json', 'tgc-actors.json', 'tgc-tools.json')
    cleaner.run()