# CYBERIA

Benyelles Djalil,
Ourimi Ayoub,
Bonnard Neil,

Sujet:
Étude et analyse de données de cybercriminalité
Ce TER s’inscrit dans le contexte d’une collaboration avec le laboratoire de sociologie et de sciences politiques CESDIP au sein du projet CYBERIA. Ce dernier vise à étudier les pratiques, distribution dans le temps et l’espace, modes opératoires, des actes cybercriminels.
L’objectif de ce projet est d’identifier et étudier des jeux de données relatifs à la cybercriminalité, puis d’expérimenter des techniques d’analyse de données, notamment en s’appuyant sur des modèles de langage, afin d’extraire des informations pertinentes pour les chercheurs en sciences sociales.
Les tâches à réaliser sont donc :
• étudier les jeux de données disponibles (Threat Group Cards: A Threat Actor Encyclopedia, …),
• collecter et préparer les données dans un format adapté,
• expérimenter des techniques d’analyse de données s’appuyant sur des modèles de langage.
Encadrement : Zoubida Kedad <zoubida.kedad@uvsq.fr>, Stéphane Lopes
<stephane.lopes@uvsq.fr>
Nombre d’étudiants : 2/3

Réunions:

- 1ère Réunion (26/01/2026): Nettoyer le jeu de donnée.
- 2ème Réunion (09/03/2026): Mise au point de ce qui a été fais. Continuer à enrichir la base et faire des analyses.


Documentation:
Le script Data_Cleaning_Pipeline.py est structuré autour d'une classe dédiée, DataCleaningPipeline, qui orchestre le cycle complet de transformation des données, du chargement initial à l'exportation finale. Au cœur de ce processus, la méthode de nettoyage procède à une normalisation rigoureuse des entrées pour pallier l'hétérogénéité des sources de renseignement sur les menaces (Cyber Threat Intelligence). Pour chaque entité, le script garantit d'abord la présence d'un identifiant unique (UUID), généré dynamiquement si nécessaire, ce qui est indispensable pour maintenir la cohérence des relations au sein du futur graphe Neo4j.

Le pipeline se concentre ensuite sur le traitement du dictionnaire des métadonnées (meta), où il analyse de manière spécifique les attributs clés tels que les pays sponsors, les secteurs ciblés, les outils utilisés et les techniques MITRE ATT&CK. La logique interne du script résout systématiquement les conflits de types de données : elle détecte si une valeur est stockée sous forme de simple chaîne de caractères ou de liste, et convertit l'ensemble en un format de liste uniforme. Cette étape de standardisation est cruciale pour l'analyse automatisée, car elle assure que chaque attribut, qu'il s'agisse de motivations ou de vecteurs d'attaque, possède une structure prévisible. Enfin, le module sauvegarde les données transformées dans le fichier threat-actor-cleaned.json, offrant ainsi un jeu de données "propre" et prêt pour les expérimentations avec des modèles de langage.

Le script import_neo4j.py assure l'intégration finale des données du projet CYBERIA dans une base de données orientée graphe. En s'appuyant sur la classe CyberImporter, il transforme les fichiers JSON nettoyés en un réseau d'entités interconnectées, facilitant l'analyse des modes opératoires pour les chercheurs en sciences sociales. L'utilisation stratégique de la clause Cypher MERGE garantit l'unicité des données et évite toute redondance lors de l'injection massive d'informations. Ce module structure l'écosystème autour de l'acteur cybercriminel, en générant des relations dynamiques vers ses cibles, ses outils et ses commanditaires présumés. Cette approche relationnelle permet d'identifier visuellement des corrélations complexes et des tendances au sein de la cybercriminalité.