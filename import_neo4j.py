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

        # 2. Gestion de la temporalité
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

        # --- NOUVEAU : GESTION DÉTAILLÉE DES PAYS ET RÉGIMES ---
        country_name = meta.get('cfr-suspected-state-sponsor')
        if country_name:
            # On récupère les infos de régime
            regime_code = meta.get('political_regime_code')
            regime_label = meta.get('political_regime_label', "Unknown")

            # On crée/met à jour le pays avec ses propriétés de régime
            tx.run("""
                MERGE (c:Country {name: $c_name})
                SET c.regime_code = $r_code, 
                    c.regime_label = $r_label
                WITH c
                MATCH (a:Actor {name: $a_name})
                MERGE (a)-[:SPONSORED_BY]->(c)
            """, c_name=country_name, r_code=regime_code, r_label=regime_label, a_name=actor_name)

        # 3. Fonction helper pour les autres relations (Cibles, Outils, etc.)
        def add_rel(label, rel_type, field):
            # On ignore 'cfr-suspected-state-sponsor' ici car traité juste au-dessus
            if field == "cfr-suspected-state-sponsor": return
            
            vals = meta.get(field, [])
            for v in ([vals] if isinstance(vals, str) else vals or []):
                query = f"""
                    MERGE (target:{label} {{name: $v_name}})
                    WITH target
                    MATCH (a:Actor {{name: $a_name}})
                    MERGE (a)-[:{rel_type}]->(target)
                """
                tx.run(query, v_name=v, a_name=actor_name)

        # Création des connexions restantes
        add_rel("Target", "TARGETS", "cti_targets")
        add_rel("Tool", "USES_TOOL", "cti_tools")
        add_rel("Technique", "EMPLOYS", "mitre_techniques")
        add_rel("Motivation", "HAS_MOTIVATION", "cti_motivation")

# --- EXECUTION ---
importer = CyberImporter(URI, USER, PASSWORD)
importer.import_json('threat-actor-cleaned.json')
importer.close()
print("Importation terminée ! Les régimes politiques sont maintenant dans le graphe.")