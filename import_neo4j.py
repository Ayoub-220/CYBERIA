import json
from neo4j import GraphDatabase

# --- CONFIGURATION ---
URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "Cyberia123@"

class CyberImporter:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def import_json(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        with self.driver.session() as session:
            for entry in data:
                session.execute_write(self._create_nodes_and_rels, entry)

    @staticmethod
    def _create_nodes_and_rels(tx, entry):
        actor_name = entry.get('value')
        if not actor_name: return

        # 1. Créer l'Acteur principal
        tx.run("""
            MERGE (a:Actor {name: $name})
            SET a.uuid = $uuid, a.description = $desc
        """, name=actor_name, uuid=entry.get('uuid'), desc=entry.get('description'))

        # --- NOUVEAU : GESTION DE LA TEMPORALITÉ ---
        year = entry.get('year_created')
        if year and year != "Unknown":
            tx.run("""
                MERGE (y:Year {value: $year})
                WITH y
                MATCH (a:Actor {name: $a_name})
                MERGE (a)-[:CREATED_IN]->(y)
            """, year=year, a_name=actor_name)

        meta = entry.get('meta', {})
        if not isinstance(meta, dict): return

        # 2. Fonction helper pour créer les relations (inchangée)
        def add_rel(label, rel_type, field):
            vals = meta.get(field, [])
            for v in ([vals] if isinstance(vals, str) else vals or []):
                query = f"""
                    MERGE (target:{label} {{name: $v_name}})
                    WITH target
                    MATCH (a:Actor {{name: $a_name}})
                    MERGE (a)-[:{rel_type}]->(target)
                """
                tx.run(query, v_name=v, a_name=actor_name)

        # Création des différentes connexions
        add_rel("Country", "SPONSORED_BY", "cfr-suspected-state-sponsor")
        add_rel("Target", "TARGETS", "cti_targets")
        add_rel("Tool", "USES_TOOL", "cti_tools")
        add_rel("Technique", "EMPLOYS", "mitre_techniques")
        add_rel("Motivation", "HAS_MOTIVATION", "cti_motivation")

# --- EXECUTION ---
importer = CyberImporter(URI, USER, PASSWORD)
importer.import_json('threat-actor-cleaned.json')
importer.close()
print("Importation terminée ! La dimension temporelle est maintenant intégrée.")