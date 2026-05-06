import json
from neo4j import GraphDatabase
import time
from datetime import datetime

# --- CONFIGURATION ---
URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "Cyberia123@"

class CyberImporter:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def log(self, message, type="INFO"):
        symbol = "✅" if type == "SUCCESS" else "⚠️" if type == "ERROR" else "ℹ️ "
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {symbol} {message}")

    def import_json(self, file_path):
        self.log(f"Ouverture du fichier {file_path}...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            self.log(f"Erreur lecture fichier : {e}", "ERROR")
            return

        total = len(data)
        success = 0
        
        self.log(f"Début de l'importation de {total} acteurs dans Neo4j.")
        start_time = time.time()

        with self.driver.session() as session:
            for i, entry in enumerate(data, 1):
                try:
                    session.execute_write(self._create_nodes_and_rels, entry)
                    success += 1
                    if i % 100 == 0:
                        self.log(f"Progression : {i}/{total}...")
                except Exception as e:
                    self.log(f"Erreur sur l'acteur {entry.get('value')} : {e}", "ERROR")

        duration = round(time.time() - start_time, 2)
        self.log(f"Importation terminée en {duration}s. {success} acteurs importés.", "SUCCESS")

    @staticmethod
    def _create_nodes_and_rels(tx, entry):
        actor_name = entry.get('value')
        if not actor_name: return

        # 1. Création/Mise à jour de l'Acteur
        tx.run("""
            MERGE (a:Actor {name: $name})
            SET a.uuid = $uuid, a.description = $desc
        """, name=actor_name, uuid=entry.get('uuid'), desc=entry.get('description'))

        # 2. Lien temporel (Année de création)
        year = entry.get('year_created')
        if year and year != "Unknown":
            tx.run("""
                MERGE (y:Year {value: $year})
                WITH y
                MATCH (a:Actor {name: $a_name})
                MERGE (a)-[:CREATED_IN]->(y)
            """, year=year, a_name=actor_name)

        meta = entry.get('meta', {})

        # 3. Nœud Pays avec Enrichissement GÉOPOLITIQUE et MILITAIRE
        country_name = meta.get('cfr-suspected-state-sponsor')
        if country_name:
            tx.run("""
                MERGE (c:Country {name: $c_name})
                SET c.regime_label = $r_label,
                    c.regime_code = $r_code,
                    c.militarisation_score = $g_score,
                    c.militarisation_rank = $g_rank
                WITH c
                MATCH (a:Actor {name: $a_name})
                MERGE (a)-[:SPONSORED_BY]->(c)
            """, 
            c_name=country_name, 
            r_label=meta.get('political_regime_label'),
            r_code=meta.get('political_regime_code'),
            g_score=meta.get('gmi_score'),
            g_rank=meta.get('gmi_rank'),
            a_name=actor_name)

        # 4. Autres relations (Cibles, Outils, Techniques, Motivations)
        def add_list_rels(label, rel_type, field):
            if field == "cfr-suspected-state-sponsor": return
            vals = meta.get(field, [])
            for v in ([vals] if isinstance(vals, str) else vals or []):
                tx.run(f"""
                    MERGE (target:{label} {{name: $v_name}})
                    WITH target
                    MATCH (a:Actor {{name: $a_name}})
                    MERGE (a)-[:{rel_type}]->(target)
                """, v_name=v, a_name=actor_name)

        add_list_rels("Target", "TARGETS", "cti_targets")
        add_list_rels("Tool", "USES_TOOL", "cti_tools")
        add_list_rels("Technique", "EMPLOYS", "mitre_techniques")
        add_list_rels("Motivation", "HAS_MOTIVATION", "cti_motivation")

# --- EXECUTION ---
if __name__ == "__main__":
    importer = CyberImporter(URI, USER, PASSWORD)
    importer.import_json('threat-actor-cleaned.json')
    importer.close()