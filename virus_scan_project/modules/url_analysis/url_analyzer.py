# modules/url_analysis/url_analyzer.py
import re
import socket
import ssl
import urllib.parse
import requests
from bs4 import BeautifulSoup
import hashlib
import json
import time
import threading
from datetime import datetime
import os
import tldextract

class URLAnalyzer:
    def __init__(self, cache_dir="url_cache", rules_dir="url_rules"):
        self.cache_dir = cache_dir
        self.rules_dir = rules_dir
        self.phishing_patterns = self._load_phishing_patterns()
        self.malicious_patterns = self._load_malicious_patterns()
        
        # Créer les répertoires nécessaires
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.rules_dir, exist_ok=True)
    
    def _load_phishing_patterns(self):
        """Charge les motifs de phishing depuis un fichier"""
        patterns_file = os.path.join(self.rules_dir, "phishing_patterns.json")
        
        # Créer un fichier de patterns par défaut s'il n'existe pas
        if not os.path.exists(patterns_file):
            default_patterns = {
                "keywords": [
                    "login", "log-in", "sign-in", "signin", "account", "password", "secure", "update",
                    "banking", "confirm", "verify", "wallet", "authenticate", "authorization"
                ],
                "domains": [
                    "paypal", "apple", "microsoft", "amazon", "facebook", "google", "netflix",
                    "bank", "secure", "account", "login", "signin"
                ],
                "url_patterns": [
                    r"(bank|secure|account|login|signin).*\.(tk|gq|ml|ga|cf)$",
                    r"(paypal|apple|microsoft|amazon|facebook|google).*\.([^com]|com.[a-z]{2,})$"
                ]
            }
            
            with open(patterns_file, "w") as f:
                json.dump(default_patterns, f, indent=2)
        
        # Charger les patterns
        try:
            with open(patterns_file, "r") as f:
                return json.load(f)
        except:
            return {
                "keywords": [],
                "domains": [],
                "url_patterns": []
            }
    
    def _load_malicious_patterns(self):
        """Charge les motifs de contenu malveillant depuis un fichier"""
        patterns_file = os.path.join(self.rules_dir, "malicious_patterns.json")
        
        # Créer un fichier de patterns par défaut s'il n'existe pas
        if not os.path.exists(patterns_file):
            default_patterns = {
                "javascript": [
                    r"eval\s*\(.*(?:unescape|fromCharCode|atob)\s*\(",
                    r"document\.write\s*\(\s*(?:unescape|fromCharCode|atob)",
                    r"(?:document|window)\.location(?:\.href)?\s*=",
                    r"<iframe.*?src\s*=\s*['\"](?:https?:)?\/\/.*?['\"].*?>",
                    r"<script.*?src\s*=\s*['\"](?:https?:)?\/\/.*?['\"].*?><\/script>"
                ],
                "exploit_kits": [
                    r"\.jar\?[a-zA-Z0-9]{20,}=",
                    r"\.swf\?[a-zA-Z0-9]{20,}=",
                    r"\.cgi\?[a-zA-Z0-9]{20,}="
                ],
                "blacklist_extensions": [
                    r"\.exe$", r"\.zip$", r"\.jar$", r"\.bat$", r"\.vbs$", r"\.ps1$"
                ]
            }
            
            with open(patterns_file, "w") as f:
                json.dump(default_patterns, f, indent=2)
        
        # Charger les patterns
        try:
            with open(patterns_file, "r") as f:
                return json.load(f)
        except:
            return {
                "javascript": [],
                "exploit_kits": [],
                "blacklist_extensions": []
            }
    
    def analyze_url(self, url):
        """Analyse complète d'une URL"""
        # Vérifier et nettoyer l'URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Génère un ID unique pour cette analyse
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        cache_file = os.path.join(self.cache_dir, f"{url_hash}.json")
        
        # Vérifier le cache
        if os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                cached_data = json.load(f)
            
            # Si le cache est récent (moins de 24 heures), l'utiliser
            if time.time() - cached_data.get("timestamp", 0) < 24 * 3600:
                return cached_data
        
        # Initialiser les résultats
        results = {
            "url": url,
            "url_hash": url_hash,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": time.time(),
            "url_analysis": self._analyze_url_structure(url),
            "dns_analysis": self._analyze_dns(url),
            "certificate_analysis": None,
            "content_analysis": None,
            "phishing_analysis": None,
            "malware_analysis": None,
            "overall_risk": {
                "score": 0,
                "level": "Inconnu",
                "indicators": []
            }
        }
        
        try:
            # Analyse du certificat SSL/TLS (pour HTTPS)
            if url.startswith('https://'):
                results["certificate_analysis"] = self._analyze_certificate(url)
            
            # Analyse du contenu de la page (avec timeout)
            content_thread = threading.Thread(target=self._analyze_content, args=(url, results))
            content_thread.daemon = True
            content_thread.start()
            content_thread.join(10)  # Timeout de 10 secondes
            
            # Vérification de phishing
            results["phishing_analysis"] = self._check_phishing(url, results)
            
            # Recherche de contenu malveillant
            if results["content_analysis"] and results["content_analysis"].get("html"):
                results["malware_analysis"] = self._check_malware(results["content_analysis"]["html"])
            
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
    
    def _analyze_url_structure(self, url):
        """Analyse la structure de l'URL"""
        parsed_url = urllib.parse.urlparse(url)
        ext = tldextract.extract(url)
        
        # Compter les caractères spéciaux dans l'URL
        special_chars = sum(1 for c in url if not c.isalnum() and c not in '/:.-_')
        
        # Analyse des paramètres de requête
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Vérifier les redirections dans l'URL
        has_redirect = False
        redirect_url = None
        for param in query_params.values():
            for value in param:
                if value.startswith(('http://', 'https://')):
                    has_redirect = True
                    redirect_url = value
                    break
        
        # Vérifier si l'URL utilise l'encodage d'adresse IP
        is_ip_url = False
        try:
            socket.inet_aton(parsed_url.netloc)
            is_ip_url = True
        except:
            pass
        
        # Vérifier les caractères Unicode suspects
        has_unicode_chars = any(ord(c) > 127 for c in url)
        
        # Vérifier les domaines suspects
        suspicious_tlds = ['.tk', '.gq', '.ml', '.ga', '.cf', '.top', '.xyz', '.info']
        is_suspicious_tld = any(ext.suffix.endswith(tld) for tld in suspicious_tlds)
        
        # Analyser les sous-domaines
        subdomains = ext.subdomain.split('.')
        
        # Repérer les noms de domaine connus dans les sous-domaines (marque-domination)
        known_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'google']
        has_brand_subdomain = any(brand in subdomains for brand in known_brands)
        
        return {
            "scheme": parsed_url.scheme,
            "netloc": parsed_url.netloc,
            "path": parsed_url.path,
            "params": parsed_url.params,
            "query": parsed_url.query,
            "fragment": parsed_url.fragment,
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "query_params": query_params,
            "special_chars_count": special_chars,
            "has_redirect": has_redirect,
            "redirect_url": redirect_url,
            "is_ip_url": is_ip_url,
            "has_unicode_chars": has_unicode_chars,
            "is_suspicious_tld": is_suspicious_tld,
            "has_brand_subdomain": has_brand_subdomain,
            "length": len(url)
        }
    
    def _analyze_dns(self, url):
        """Analyse DNS de l'URL"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Supprimer le port s'il est présent
        if ':' in domain:
            domain = domain.split(':')[0]
        
        try:
            # Résolution DNS
            ip_addresses = []
            for info in socket.getaddrinfo(domain, None):
                if info[4][0] not in ip_addresses:
                    ip_addresses.append(info[4][0])
            
            # Résolution inverse
            try:
                reverse_dns = socket.gethostbyaddr(ip_addresses[0])[0]
            except:
                reverse_dns = None
            
            return {
                "domain": domain,
                "ip_addresses": ip_addresses,
                "reverse_dns": reverse_dns,
                "resolved": True
            }
        except Exception as e:
            return {
                "domain": domain,
                "error": str(e),
                "resolved": False
            }
    
    def _analyze_certificate(self, url):
        """Analyse le certificat SSL/TLS d'une URL HTTPS"""
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]
        port = parsed_url.port or 443
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Vérifier la date d'expiration
                    not_after = cert.get('notAfter')
                    not_before = cert.get('notBefore')
                    
                    # Vérifier si le certificat correspond au domaine
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Vérifier les SAN (Subject Alternative Names)
                    san = []
                    for ext in cert.get('subjectAltName', []):
                        san.append(ext)
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get('version'),
                        "not_before": not_before,
                        "not_after": not_after,
                        "subject_alt_names": san,
                        "has_expired": ssl.cert_time_to_seconds(not_after) < time.time(),
                        "is_valid": hostname in str(san) or hostname == subject.get('commonName'),
                        "is_self_signed": subject == issuer
                    }
        except Exception as e:
            return {
                "error": str(e),
                "has_certificate": False
            }
    
    def _analyze_content(self, url, results):
        """Analyse le contenu de la page web"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            # Analyser la réponse
            content_analysis = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "size": len(response.content),
                "final_url": response.url,
                "redirected": response.url != url,
                "redirect_history": [h.url for h in response.history]
            }
            
            # Analyser le contenu HTML si présent
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extraire les informations de la page
                content_analysis["html"] = response.text
                content_analysis["title"] = soup.title.string if soup.title else None
                
                # Extraire les scripts
                scripts = []
                for script in soup.find_all('script'):
                    script_info = {
                        "src": script.get('src'),
                        "inline": bool(script.string),
                        "length": len(script.string) if script.string else 0
                    }
                    scripts.append(script_info)
                
                content_analysis["scripts"] = scripts
                
                # Extraire les iframes
                iframes = []
                for iframe in soup.find_all('iframe'):
                    iframe_info = {
                        "src": iframe.get('src'),
                        "width": iframe.get('width'),
                        "height": iframe.get('height'),
                        "hidden": iframe.get('hidden') is not None or iframe.get('style') == 'display:none'
                    }
                    iframes.append(iframe_info)
                
                content_analysis["iframes"] = iframes
                
                # Extraire les liens
                links = []
                for a in soup.find_all('a', href=True):
                    links.append(a['href'])
                
                content_analysis["links"] = links
                
                # Extraire les formulaires
                forms = []
                for form in soup.find_all('form'):
                    form_info = {
                        "action": form.get('action'),
                        "method": form.get('method', 'get').upper(),
                        "inputs": []
                    }
                    
                    for input_tag in form.find_all('input'):
                        input_info = {
                            "type": input_tag.get('type'),
                            "name": input_tag.get('name'),
                            "id": input_tag.get('id'),
                            "is_password": input_tag.get('type') == 'password'
                        }
                        form_info["inputs"].append(input_info)
                    
                    forms.append(form_info)
                
                content_analysis["forms"] = forms
                
                # Vérifier la présence de formulaires de login
                content_analysis["has_login_form"] = any(
                    any(input_info["is_password"] for input_info in form["inputs"])
                    for form in forms
                )
            
            results["content_analysis"] = content_analysis
            
        except Exception as e:
            results["content_analysis"] = {
                "error": str(e),
                "accessible": False
            }
    
    def _check_phishing(self, url, results):
        """Analyse l'URL pour détecter les signes de phishing"""
        url_analysis = results["url_analysis"]
        content_analysis = results.get("content_analysis", {})
        
        phishing_indicators = []
        confidence_score = 0
        
        # Vérifier la structure de l'URL
        if url_analysis["is_ip_url"]:
            phishing_indicators.append("L'URL utilise une adresse IP au lieu d'un nom de domaine")
            confidence_score += 20
        
        if url_analysis["has_unicode_chars"]:
            phishing_indicators.append("L'URL contient des caractères Unicode suspects")
            confidence_score += 30
        
        if url_analysis["is_suspicious_tld"]:
            phishing_indicators.append("L'URL utilise un TLD suspect")
            confidence_score += 15
        
        if url_analysis["has_brand_subdomain"]:
            phishing_indicators.append("L'URL contient une marque connue en sous-domaine")
            confidence_score += 25
        
        if url_analysis["special_chars_count"] > 5:
            phishing_indicators.append(f"L'URL contient beaucoup de caractères spéciaux ({url_analysis['special_chars_count']})")
            confidence_score += 10
        
        if url_analysis["has_redirect"]:
            phishing_indicators.append("L'URL contient une redirection vers un autre site")
            confidence_score += 15
        
        # Vérifier le contenu de la page
        if content_analysis.get("has_login_form", False):
            phishing_indicators.append("La page contient un formulaire de connexion")
            confidence_score += 10
        
        # Vérifier les mots-clés de phishing dans l'URL
        for keyword in self.phishing_patterns.get("keywords", []):
            if keyword.lower() in url.lower():
                phishing_indicators.append(f"L'URL contient le mot-clé suspect '{keyword}'")
                confidence_score += 5
        
        # Vérifier les domaines sensibles
        for brand in self.phishing_patterns.get("domains", []):
            if brand.lower() in url_analysis["domain"].lower() and brand.lower() != url_analysis["domain"].lower():
                phishing_indicators.append(f"L'URL imite la marque '{brand}'")
                confidence_score += 25
        
        # Vérifier les motifs d'URL suspects
        for pattern in self.phishing_patterns.get("url_patterns", []):
            if re.search(pattern, url, re.IGNORECASE):
                phishing_indicators.append("L'URL correspond à un motif suspect connu")
                confidence_score += 20
        
        # Déterminer le niveau de risque
        risk_level = "Faible"
        if confidence_score > 20:
            risk_level = "Moyen"
        if confidence_score > 40:
            risk_level = "Élevé"
        if confidence_score > 60:
            risk_level = "Critique"
        
        return {
            "is_phishing": confidence_score > 40,
            "confidence_score": min(confidence_score, 100),
            "risk_level": risk_level,
            "indicators": phishing_indicators
        }
    
    def _check_malware(self, html_content):
        """Analyse le contenu HTML pour détecter des indicateurs de malware"""
        malware_indicators = []
        confidence_score = 0
        
        # Vérifier les scripts malveillants
        for pattern in self.malicious_patterns.get("javascript", []):
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                malware_indicators.append(f"Script potentiellement malveillant détecté: {pattern}")
                confidence_score += 20
        
        # Vérifier les motifs d'exploit kits
        for pattern in self.malicious_patterns.get("exploit_kits", []):
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                malware_indicators.append(f"Motif d'Exploit Kit détecté: {pattern}")
                confidence_score += 30
        
        # Vérifier les liens vers des fichiers suspects
        for pattern in self.malicious_patterns.get("blacklist_extensions", []):
            matches = re.findall(f"href=['\"].*{pattern}", html_content, re.IGNORECASE)
            if matches:
                malware_indicators.append(f"Lien vers un fichier suspect détecté: {pattern}")
                confidence_score += 15
        
        # Détecter les iframes cachés
        hidden_iframes = re.findall(r"<iframe[^>]*(?:hidden|display\s*:\s*none|height\s*=\s*['\"]\s*0\s*['\"]|width\s*=\s*['\"]\s*0\s*['\"])[^>]*>", html_content, re.IGNORECASE)
        if hidden_iframes:
            malware_indicators.append("Iframe caché détecté")
            confidence_score += 25
        
        # Détecter l'obfuscation de code
        if any(term in html_content.lower() for term in ["eval(", "document.write(", "escape(", "unescape(", "fromcharcode", "atob("]):
            malware_indicators.append("Obfuscation de code JavaScript détectée")
            confidence_score += 20
        
        # Déterminer le niveau de risque
        risk_level = "Faible"
        if confidence_score > 20:
            risk_level = "Moyen"
        if confidence_score > 40:
            risk_level = "Élevé"
        if confidence_score > 60:
            risk_level = "Critique"

       
       
        return {
           "is_malicious": confidence_score > 40,
           "confidence_score": min(confidence_score, 100),
           "risk_level": risk_level,
           "indicators": malware_indicators
       }
   
    def _assess_risk(self, results):
       """Évalue le risque global de l'URL"""
       risk_score = 0
       risk_indicators = []
       
       # Accumule les indicateurs de risque des différentes analyses
       url_analysis = results["url_analysis"]
       dns_analysis = results["dns_analysis"]
       certificate_analysis = results.get("certificate_analysis", {})
       phishing_analysis = results.get("phishing_analysis", {})
       malware_analysis = results.get("malware_analysis", {})
       
       # Indicateurs de structure d'URL
       if url_analysis["is_ip_url"]:
           risk_score += 20
           risk_indicators.append("URL utilise une adresse IP directe")
       
       if url_analysis["has_redirect"]:
           risk_score += 15
           risk_indicators.append("URL contient une redirection")
       
       if url_analysis["is_suspicious_tld"]:
           risk_score += 15
           risk_indicators.append("TLD suspect")
       
       # Indicateurs de certificat SSL
       if certificate_analysis.get("has_expired", False):
           risk_score += 30
           risk_indicators.append("Certificat SSL expiré")
           
       if certificate_analysis.get("is_self_signed", False):
           risk_score += 25
           risk_indicators.append("Certificat SSL auto-signé")
           
       if certificate_analysis.get("is_valid", True) is False:
           risk_score += 30
           risk_indicators.append("Certificat SSL invalide pour ce domaine")
       
       # Indicateurs de phishing
       if phishing_analysis:
           risk_score += phishing_analysis.get("confidence_score", 0) * 0.7
           risk_indicators.extend(phishing_analysis.get("indicators", []))
       
       # Indicateurs de malware
       if malware_analysis:
           risk_score += malware_analysis.get("confidence_score", 0) * 0.8
           risk_indicators.extend(malware_analysis.get("indicators", []))
       
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