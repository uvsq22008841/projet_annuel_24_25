# modules/ip_analysis/ip_analyzer.py
import socket
import ipaddress
import re
import subprocess
import json
import os
import time
import threading
from datetime import datetime
import hashlib
import requests

class IPAnalyzer:
    def __init__(self, cache_dir="ip_cache", data_dir="ip_data"):
        self.cache_dir = cache_dir
        self.data_dir = data_dir
        
        # Créer les répertoires nécessaires
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Charger la base de données des ASN (si disponible)
        self.asn_database = self._load_asn_database()
        
        # Charger la base de données des réputations (si disponible)
        self.reputation_database = self._load_reputation_database()
    
    def _load_asn_database(self):
        """Charge la base de données des ASN"""
        asn_file = os.path.join(self.data_dir, "asn_database.json")
        
        # Créer un fichier par défaut s'il n'existe pas
        if not os.path.exists(asn_file):
            default_asn = {}
            with open(asn_file, "w") as f:
                json.dump(default_asn, f, indent=2)
        
        # Charger la base de données
        try:
            with open(asn_file, "r") as f:
                return json.load(f)
        except:
            return {}
    
    def _load_reputation_database(self):
        """Charge la base de données des réputations d'IP"""
        reputation_file = os.path.join(self.data_dir, "reputation_database.json")
        
        # Créer un fichier par défaut s'il n'existe pas
        if not os.path.exists(reputation_file):
            default_reputation = {
                "malicious": [],
                "suspicious": [],
                "known_scanners": [],
                "known_proxies": [],
                "known_tor_exits": []
            }
            with open(reputation_file, "w") as f:
                json.dump(default_reputation, f, indent=2)
        
        # Charger la base de données
        try:
            with open(reputation_file, "r") as f:
                return json.load(f)
        except:
            return {
                "malicious": [],
                "suspicious": [],
                "known_scanners": [],
                "known_proxies": [],
                "known_tor_exits": []
            }
    
    def analyze_ip(self, ip_address):
        """Analyse complète d'une adresse IP"""
        # Vérifier et nettoyer l'adresse IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            ip_address = str(ip_obj)
        except ValueError:
            return {
                "error": "Adresse IP invalide",
                "valid": False
            }
        
        # Génère un ID unique pour cette analyse
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
        cache_file = os.path.join(self.cache_dir, f"{ip_hash}.json")
        
        # Vérifier le cache
        if os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                cached_data = json.load(f)
            
            # Si le cache est récent (moins de 24 heures), l'utiliser
            if time.time() - cached_data.get("timestamp", 0) < 24 * 3600:
                return cached_data
        
        # Initialiser les résultats
        results = {
            "ip_address": ip_address,
            "ip_hash": ip_hash,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": time.time(),
            "basic_info": self._get_basic_info(ip_address),
            "reverse_dns": None,
            "geolocation": None,
            "asn_info": None,
            "port_scan": None,
            "reputation": None,
            "overall_risk": {
                "score": 0,
                "level": "Inconnu",
                "indicators": []
            }
        }
        
        try:
            # Résolution DNS inverse
            results["reverse_dns"] = self._get_reverse_dns(ip_address)
            
            # Information de géolocalisation
            results["geolocation"] = self._get_geolocation(ip_address)
            
            # Information ASN
            results["asn_info"] = self._get_asn_info(ip_address)
            
            # Lancer l'analyse de ports dans un thread séparé (avec timeout)
            port_thread = threading.Thread(target=self._scan_ports, args=(ip_address, results))
            port_thread.daemon = True
            port_thread.start()
            port_thread.join(15)  # Timeout de 15 secondes
            
            # Vérification de réputation
            results["reputation"] = self._check_reputation(ip_address)
            
            # Évaluation du risque global
            results["overall_risk"] = self._assess_risk(results)
            
            # Mettre en cache les résultats
            with open(cache_file, "w") as f:
                json.dump(results, f, indent=2)
            
            return results
            
        except Exception as e:
            # En cas d'erreur, on retourne ce qu'on a déjà analysé
            results["error"] = str(e)
            return results
    
    def _get_basic_info(self, ip_address):
        """Obtient les informations de base sur l'adresse IP"""
        ip_obj = ipaddress.ip_address(ip_address)
        
        return {
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved": ip_obj.is_reserved,
            "is_loopback": ip_obj.is_loopback,
            "is_link_local": ip_obj.is_link_local
        }
    
    def _get_reverse_dns(self, ip_address):
        """Obtient la résolution DNS inverse"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except:
            return None
    
    def _get_geolocation(self, ip_address):
        """Obtient la géolocalisation de l'adresse IP"""
        # Note: Cette fonction utilise une API fictive
        # Dans une implémentation réelle, vous devriez utiliser une base de données locale comme GeoLite2
        try:
            # Simulation de base de données de géolocalisation locale
            geo_file = os.path.join(self.data_dir, "geo_sample.json")
            
            # Créer un fichier de géolocalisation exemple s'il n'existe pas
            if not os.path.exists(geo_file):
                sample_geo = {
                    "1.1.1.1": {
                        "country": "Australia",
                        "country_code": "AU",
                        "city": "Research",
                        "region": "Victoria",
                        "latitude": -37.7,
                        "longitude": 145.1833
                    },
                    "8.8.8.8": {
                        "country": "United States",
                        "country_code": "US",
                        "city": "Mountain View",
                        "region": "California",
                        "latitude": 37.386,
                        "longitude": -122.0838
                    }
                }
                
                with open(geo_file, "w") as f:
                    json.dump(sample_geo, f, indent=2)
            
            # Charger les données de géolocalisation
            with open(geo_file, "r") as f:
                geo_data = json.load(f)
            
            # Vérifier si l'IP est dans notre base de données
            if ip_address in geo_data:
                return geo_data[ip_address]
            
            # Si l'IP n'est pas trouvée, retourner un emplacement inconnu
            return {
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "region": "Unknown",
                "latitude": 0,
                "longitude": 0
            }
            
        except Exception as e:
            return {
                "error": str(e)
            }
    
    def _get_asn_info(self, ip_address):
        """Obtient les informations ASN pour l'adresse IP"""
        # Note: Cette fonction utilise une base de données ASN fictive
        # Dans une implémentation réelle, vous devriez utiliser une base de données comme pyasn
        try:
            # Vérifier si l'IP est dans notre base de données ASN
            if ip_address in self.asn_database:
                return self.asn_database[ip_address]
            
            # Si l'IP n'est pas trouvée, simuler des informations
            if ip_address.startswith("8.8."):
                return {
                    "asn": "AS15169",
                    "name": "Google LLC",
                    "route": "8.8.8.0/24",
                    "type": "Content"
                }
            
            return {
                "asn": "Unknown",
                "name": "Unknown",
                "route": "Unknown",
                "type": "Unknown"
            }
            
        except Exception as e:
            return {
                "error": str(e)
            }
    
    def _scan_ports(self, ip_address, results):
        """Effectue un scan des ports courants"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080]
        scan_results = {}
        
        for port in common_ports:
            # Utilisation de la bibliothèque socket pour la connexion TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((ip_address, port))
                is_open = (result == 0)
                
                if is_open:
                    # Tenter d'identifier le service
                    service = self._identify_service(ip_address, port)
                    scan_results[port] = {
                        "open": True,
                        "service": service
                    }
                else:
                    scan_results[port] = {
                        "open": False
                    }
                    
            except:
                scan_results[port] = {
                    "open": False,
                    "error": "Connection failed"
                }
            
            finally:
                sock.close()
        
        results["port_scan"] = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports_count": sum(1 for port, info in scan_results.items() if info.get("open", False)),
            "ports": scan_results
        }
    
    def _identify_service(self, ip_address, port):
        """Tente d'identifier le service en cours d'exécution sur un port"""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTP/SSL",
            587: "SMTP/TLS",
            993: "IMAP/SSL",
            995: "POP3/SSL",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy"
        }
        
        # Retourner le service courant
        return common_services.get(port, "Unknown")
    
    def _check_reputation(self, ip_address):
        """Vérifie la réputation de l'adresse IP"""
        reputation = {
            "malicious": False,
            "suspicious": False,
            "is_proxy": False,
            "is_tor_exit": False,
            "is_scanner": False,
            "categories": [],
            "score": 0,
            "sources": []
        }
        
        # Vérifier contre les listes locales
        if ip_address in self.reputation_database.get("malicious", []):
            reputation["malicious"] = True
            reputation["score"] += 80
            reputation["sources"].append("Local malicious IP database")
            reputation["categories"].append("Malicious")
        
        if ip_address in self.reputation_database.get("suspicious", []):
            reputation["suspicious"] = True
            reputation["score"] += 50
            reputation["sources"].append("Local suspicious IP database")
            reputation["categories"].append("Suspicious")
        
        if ip_address in self.reputation_database.get("known_scanners", []):
            reputation["is_scanner"] = True
            reputation["score"] += 60
            reputation["sources"].append("Known scanner list")
            reputation["categories"].append("Scanner")
        
        if ip_address in self.reputation_database.get("known_proxies", []):
            reputation["is_proxy"] = True
            reputation["score"] += 40
            reputation["sources"].append("Known proxy list")
            reputation["categories"].append("Proxy")
        
        if ip_address in self.reputation_database.get("known_tor_exits", []):
            reputation["is_tor_exit"] = True
            reputation["score"] += 60
            reputation["sources"].append("TOR exit node list")
            reputation["categories"].append("TOR Exit Node")
        
        # Déterminer le niveau de risque
        risk_level = "Faible"
        if reputation["score"] > 20:
            risk_level = "Moyen"
        if reputation["score"] > 50:
            risk_level = "Élevé"
        if reputation["score"] > 75:
            risk_level = "Critique"
        
        reputation["risk_level"] = risk_level
        
        return reputation
    
    def _assess_risk(self, results):
        """Évalue le risque global de l'adresse IP"""
        risk_score = 0
        risk_indicators = []
        
        # Évaluer le type d'adresse
        basic_info = results["basic_info"]
        if not basic_info.get("is_global", True):
            # Les IPs privées sont généralement moins risquées
            risk_score += 5
            risk_indicators.append("Adresse IP privée")
        
        # Évaluer les ports ouverts
        port_scan = results.get("port_scan", {})
        open_ports_count = port_scan.get("open_ports_count", 0)
        
        if open_ports_count > 5:
            risk_score += 20
            risk_indicators.append(f"{open_ports_count} ports ouverts")
        elif open_ports_count > 0:
            risk_score += 10
            risk_indicators.append(f"{open_ports_count} ports ouverts")
        
        # Vérifier les services sensibles
        ports = port_scan.get("ports", {})
        sensitive_services = ["FTP", "Telnet", "RDP", "VNC"]
        
        for port, info in ports.items():
            if info.get("open", False) and info.get("service", "") in sensitive_services:
                risk_score += 15
                risk_indicators.append(f"Service sensible détecté: {info['service']} (port {port})")
        
        # Évaluer la réputation
        reputation = results.get("reputation", {})
        if reputation.get("malicious", False):
            risk_score += 80
            risk_indicators.append("IP signalée comme malveillante")
        
        if reputation.get("suspicious", False):
            risk_score += 50
            risk_indicators.append("IP signalée comme suspecte")
        
        if reputation.get("is_scanner", False):
            risk_score += 60
            risk_indicators.append("IP connue pour des activités de scan")
        
        if reputation.get("is_proxy", False):
            risk_score += 30
            risk_indicators.append("IP est un proxy connu")
        
        if reputation.get("is_tor_exit", False):
            risk_score += 40
            risk_indicators.append("IP est un nœud de sortie TOR")
        
        # Ajouter les indicateurs de risque spécifiques de la réputation
        risk_indicators.extend(reputation.get("categories", []))
        
        # Déterminer le niveau de risque global
        risk_level = "Faible"
        if risk_score > 20:
            risk_level = "Moyen"
        if risk_score > 50:
            risk_level = "Élevé"
        if risk_score > 75:
            risk_level = "Critique"
        
        return {
            "score": min(round(risk_score, 1), 100),
            "level": risk_level,
            "indicators": risk_indicators
        }