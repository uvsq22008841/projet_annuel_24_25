# modules/file_analysis/signatures_manager.py
import os
import json
import hashlib
import re
import logging
import time
from datetime import datetime
import threading
import schedule

class SignaturesManager:
    def __init__(self, signatures_dir="signatures"):
        """
        Initialise le gestionnaire de signatures virales.
        
        Args:
            signatures_dir: Répertoire où sont stockées les signatures
        """
        self.signatures_dir = signatures_dir
        self.md5_signatures = {}
        self.sha1_signatures = {}
        self.sha256_signatures = {}
        self.yara_rules = {}
        self.pattern_signatures = {}
        
        # Configuration du logger
        self.logger = logging.getLogger("signatures_manager")
        self.logger.setLevel(logging.INFO)
        
        if not os.path.exists(self.signatures_dir):
            os.makedirs(self.signatures_dir)
        
        handler = logging.FileHandler(os.path.join(self.signatures_dir, "signatures.log"))
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        
        # Chargement des signatures
        self._load_signatures()
        
        # Démarrer le planificateur de mise à jour
        self._setup_update_scheduler()
    
    def _load_signatures(self):
        """Charge toutes les signatures disponibles"""
        self.logger.info("Chargement des signatures...")
        
        # Charger les signatures de hash
        self._load_hash_signatures("md5", self.md5_signatures)
        self._load_hash_signatures("sha1", self.sha1_signatures)
        self._load_hash_signatures("sha256", self.sha256_signatures)
        
        # Charger les signatures à base de motifs
        self._load_pattern_signatures()
        
        # Charger les règles YARA
        # self._load_yara_rules()
        
        self.logger.info(f"Signatures chargées: MD5={len(self.md5_signatures)}, SHA1={len(self.sha1_signatures)}, SHA256={len(self.sha256_signatures)}, Patterns={len(self.pattern_signatures)}")
    
    def _load_hash_signatures(self, hash_type, signatures_dict):
        """Charge les signatures de hash d'un type spécifique"""
        signatures_file = os.path.join(self.signatures_dir, f"{hash_type}_signatures.json")
        
        # Créer un fichier par défaut s'il n'existe pas
        if not os.path.exists(signatures_file):
            default_signatures = {}
            with open(signatures_file, "w") as f:
                json.dump(default_signatures, f, indent=2)
        
        # Charger les signatures
        try:
            with open(signatures_file, "r") as f:
                loaded_signatures = json.load(f)
                signatures_dict.clear()
                signatures_dict.update(loaded_signatures)
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des signatures {hash_type}: {e}")
    
    def _load_pattern_signatures(self):
        """Charge les signatures à base de motifs (pour les fichiers textuels)"""
        patterns_file = os.path.join(self.signatures_dir, "pattern_signatures.json")
        
        # Créer un fichier par défaut s'il n'existe pas
        if not os.path.exists(patterns_file):
            default_patterns = {
                "javascript": [
                    {
                        "name": "Obfuscated JS",
                        "pattern": r"eval\s*\(.*(?:unescape|fromCharCode|atob)\s*\(",
                        "description": "JavaScript obfusqué utilisant des fonctions de décodage",
                        "severity": "medium",
                        "category": "obfuscation"
                    }
                ],
                "html": [
                    {
                        "name": "Hidden Iframe",
                        "pattern": r"<iframe[^>]*(?:hidden|display\s*:\s*none|height\s*=\s*['\"]\s*0\s*['\"]|width\s*=\s*['\"]\s*0\s*['\"])[^>]*>",
                        "description": "Iframe caché potentiellement malveillant",
                        "severity": "high",
                        "category": "exploitation"
                    }
                ],
                "php": [
                    {
                        "name": "PHP Shell",
                        "pattern": r"(?:system|exec|shell_exec|passthru|eval)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
                        "description": "Code PHP exécutant des commandes système basées sur des entrées utilisateur",
                        "severity": "critical",
                        "category": "webshell"
                    }
                ],
                "vbs": [
                    {
                        "name": "VBS Downloader",
                        "pattern": r"(?:CreateObject\s*\(\s*['\"]WinHttp\.WinHttpRequest['\"]|XMLHTTP)",
                        "description": "Script VBS faisant des requêtes HTTP",
                        "severity": "medium",
                        "category": "downloader"
                    }
                ]
            }
            
            with open(patterns_file, "w") as f:
                json.dump(default_patterns, f, indent=2)
        
        # Charger les patterns
        try:
            with open(patterns_file, "r") as f:
                self.pattern_signatures = json.load(f)
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des signatures de motifs: {e}")
            self.pattern_signatures = {}
    
    def _setup_update_scheduler(self):
        """Configure un planificateur pour mettre à jour les signatures périodiquement"""
        schedule.every(24).hours.do(self.update_signatures)
        
        # Démarrer le thread de mise à jour
        update_thread = threading.Thread(target=self._run_scheduler)
        update_thread.daemon = True
        update_thread.start()
    
    def _run_scheduler(self):
        """Exécute le planificateur de mise à jour en arrière-plan"""
        while True:
            schedule.run_pending()
            time.sleep(3600)  # Vérifier toutes les heures
    
    def update_signatures(self):
        """Met à jour les signatures depuis des sources externes"""
        self.logger.info("Mise à jour des signatures...")
        # TODO: Implémentez ici la logique pour mettre à jour les signatures depuis des sources externes
        # Par exemple:
        # - Télécharger des signatures depuis un serveur central
        # - Mettre à jour les signatures à partir de sources ouvertes
        # - Télécharger des règles YARA mises à jour
        
        # Pour l'exemple, nous allons simplement simuler une mise à jour
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Ajouter une signature de test
        test_hash = hashlib.md5(f"test_malware_{update_time}".encode()).hexdigest()
        self.md5_signatures[test_hash] = {
            "name": "Test Malware",
            "type": "trojan",
            "severity": "medium",
            "added_date": update_time
        }
        
        # Enregistrer les signatures mises à jour
        self._save_hash_signatures("md5", self.md5_signatures)
        
        self.logger.info(f"Mise à jour des signatures terminée: {update_time}")
        return True
    
    def _save_hash_signatures(self, hash_type, signatures_dict):
        """Enregistre les signatures de hash dans un fichier"""
        signatures_file = os.path.join(self.signatures_dir, f"{hash_type}_signatures.json")
        
        try:
            with open(signatures_file, "w") as f:
                json.dump(signatures_dict, f, indent=2)
                
            self.logger.info(f"Signatures {hash_type} enregistrées: {len(signatures_dict)} entrées")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de l'enregistrement des signatures {hash_type}: {e}")
            return False
    
    def lookup_hash(self, file_hash, hash_type="md5"):
        """Recherche un hash dans les signatures"""
        if hash_type == "md5":
            return self.md5_signatures.get(file_hash.lower())
        elif hash_type == "sha1":
            return self.sha1_signatures.get(file_hash.lower())
        elif hash_type == "sha256":
            return self.sha256_signatures.get(file_hash.lower())
        else:
            return None
    
    def scan_content(self, content, content_type="text"):
        """Analyse le contenu textuel pour les motifs connus"""
        results = []
        
        # Déterminer les motifs à utiliser en fonction du type de contenu
        patterns = []
        
        if content_type in self.pattern_signatures:
            patterns.extend(self.pattern_signatures[content_type])
        else:
            # Si le type spécifique n'est pas trouvé, utiliser tous les motifs
            for type_patterns in self.pattern_signatures.values():
                patterns.extend(type_patterns)
        
        # Rechercher les motifs
        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                if matches:
                    result = {
                        "name": pattern_info["name"],
                        "matches": len(matches),
                        "severity": pattern_info["severity"],
                        "category": pattern_info["category"],
                        "description": pattern_info["description"],
                        "matched_content": matches[:3]  # Limiter à 3 correspondances pour éviter une taille excessive
                    }
                    
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Erreur lors de l'analyse du motif '{pattern}': {e}")
        
        return results
    
    def add_hash_signature(self, file_hash, hash_type, signature_info):
        """Ajoute une nouvelle signature de hash"""
        if hash_type == "md5":
            self.md5_signatures[file_hash.lower()] = signature_info
            return self._save
        
    # modules/file_analysis/signatures_manager.py (suite)
    def add_hash_signature(self, file_hash, hash_type, signature_info):
       """Ajoute une nouvelle signature de hash"""
       if hash_type == "md5":
           self.md5_signatures[file_hash.lower()] = signature_info
           return self._save_hash_signatures("md5", self.md5_signatures)
       elif hash_type == "sha1":
           self.sha1_signatures[file_hash.lower()] = signature_info
           return self._save_hash_signatures("sha1", self.sha1_signatures)
       elif hash_type == "sha256":
           self.sha256_signatures[file_hash.lower()] = signature_info
           return self._save_hash_signatures("sha256", self.sha256_signatures)
       else:
           return False
   
    def add_pattern_signature(self, content_type, pattern_info):
       """Ajoute une nouvelle signature de motif"""
       if content_type not in self.pattern_signatures:
           self.pattern_signatures[content_type] = []
       
       self.pattern_signatures[content_type].append(pattern_info)
       
       try:
           patterns_file = os.path.join(self.signatures_dir, "pattern_signatures.json")
           with open(patterns_file, "w") as f:
               json.dump(self.pattern_signatures, f, indent=2)
           
           return True
       except Exception as e:
           self.logger.error(f"Erreur lors de l'enregistrement des signatures de motifs: {e}")
           return False