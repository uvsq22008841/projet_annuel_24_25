# app.py
import streamlit as st
import os
import tempfile
import time
from datetime import datetime

# Importer les modules développés
from modules.auth.auth_manager import AuthManager
from modules.file_analysis.static_analyzer import StaticAnalyzer
from modules.file_analysis.sandbox_manager import SandboxManager
from modules.file_analysis.signatures_manager import SignaturesManager
from modules.url_analysis.url_analyzer import URLAnalyzer
from modules.ip_analysis.ip_analyzer import IPAnalyzer
from modules.database.db_manager import DatabaseManager

# Initialisation des services
auth_manager = AuthManager()
db_manager = DatabaseManager()
static_analyzer = StaticAnalyzer()
sandbox_manager = SandboxManager()
signatures_manager = SignaturesManager()
url_analyzer = URLAnalyzer()
ip_analyzer = IPAnalyzer()

# Configuration de la page Streamlit
st.set_page_config(
    page_title="VirusScan - Analyse de Sécurité",
    page_icon="🔒",
    layout="wide"
)

# Appliquer un style personnalisé
def apply_custom_style():
    # Votre code de style CSS existant
    st.markdown("""
    <style>
    /* Styles CSS... */
    </style>
    """, unsafe_allow_html=True)

# Fonction pour analyser un fichier
def analyze_file(file_path, user_id, sandbox_enabled=False):
    # Étape 1: Analyse statique
    static_results = static_analyzer.analyze_file(file_path)
    
    # Étape 2: Vérification des signatures
    hash_md5 = static_results["hashes"]["md5"]
    hash_sha1 = static_results["hashes"]["sha1"]
    hash_sha256 = static_results["hashes"]["sha256"]
    
    # Vérifier les hash contre les signatures connues
    md5_match = signatures_manager.lookup_hash(hash_md5, "md5")
    sha1_match = signatures_manager.lookup_hash(hash_sha1, "sha1")
    sha256_match = signatures_manager.lookup_hash(hash_sha256, "sha256")
    
    signature_matches = []
    if md5_match:
        signature_matches.append({"type": "md5", "match": md5_match})
    if sha1_match:
        signature_matches.append({"type": "sha1", "match": sha1_match})
    if sha256_match:
        signature_matches.append({"type": "sha256", "match": sha256_match})
    
    # Étape 3: Analyse comportementale (sandbox) si activée
    sandbox_results = None
    if sandbox_enabled:
        sandbox_results = sandbox_manager.run_file(file_path)
    
    # Étape 4: Insérer les résultats dans la base de données
    file_id = db_manager.insert_file(
        hash_md5=hash_md5,
        hash_sha1=hash_sha1,
        hash_sha256=hash_sha256,
        file_name=os.path.basename(file_path),
        file_size=static_results["basic_info"]["file_size"],
        file_type=static_results["basic_info"]["mime_type"],
        submitter_id=user_id
    )
    
    # Stocker les résultats d'analyse
    if file_id:
        db_manager.insert_static_analysis(
            file_id=file_id,
            mime_type=static_results["basic_info"]["mime_type"],
            analysis_result=static_results,
            risk_score=static_results["risk_assessment"]["score"],
            risk_level=static_results["risk_assessment"]["level"],
            risk_factors=static_results["risk_assessment"]["factors"]
        )
        
        if sandbox_results:
            db_manager.insert_sandbox_analysis(
                file_id=file_id,
                execution_success=sandbox_results["execution_successful"],
                execution_output=sandbox_results["execution_output"],
                processes_created=sandbox_results["processes"],
                file_operations=sandbox_results["files"],
                network_connections=sandbox_results["network"],
                analysis_result=sandbox_results,
                risk_score=sandbox_results["behavior_summary"]["risk_level"],
                risk_level=sandbox_results["behavior_summary"]["risk_level"],
                risk_factors=sandbox_results["behavior_summary"]["indicators"]
            )
    
    # Retourner les résultats combinés
    return {
        "file_id": file_id,
        "static_analysis": static_results,
        "signature_matches": signature_matches,
        "sandbox_analysis": sandbox_results,
        "overall_risk": static_results["risk_assessment"]["level"] 
                        if not sandbox_results else 
                        max(static_results["risk_assessment"]["level"], 
                            sandbox_results["behavior_summary"]["risk_level"], 
                            key=lambda x: {"Faible": 1, "Moyen": 2, "Élevé": 3, "Critique": 4}.get(x, 0))
    }

# Fonction pour analyser une URL
def analyze_url(url, user_id):
    # Analyse de l'URL
    url_results = url_analyzer.analyze_url(url)
    
    # Insérer l'URL dans la base de données
    url_id = db_manager.insert_url(
        url=url,
        domain=url_results["url_analysis"]["domain"],
        path=url_results["url_analysis"]["path"],
        scheme=url_results["url_analysis"]["scheme"],
        submitter_id=user_id
    )
    
    # Stocker les résultats d'analyse
    if url_id:
        db_manager.insert_url_analysis(
            url_id=url_id,
            url_structure=url_results["url_analysis"],
            dns_info=url_results["dns_analysis"],
            certificate_info=url_results.get("certificate_analysis"),
            content_info=url_results.get("content_analysis"),
            phishing_analysis=url_results.get("phishing_analysis"),
            malware_analysis=url_results.get("malware_analysis"),
            risk_score=url_results["overall_risk"]["score"],
            risk_level=url_results["overall_risk"]["level"],
            risk_factors=url_results["overall_risk"]["indicators"]
        )
    
    return {
        "url_id": url_id,
        "analysis": url_results
    }

# Fonction pour analyser une adresse IP
def analyze_ip(ip_address, user_id):
    # Analyse de l'IP
    ip_results = ip_analyzer.analyze_ip(ip_address)
    
    # Insérer l'IP dans la base de données
    ip_id = db_manager.insert_ip(
        ip_address=ip_address,
        ip_version=ip_results["basic_info"]["version"],
        submitter_id=user_id
    )
    
    # Stocker les résultats d'analyse
    if ip_id:
        db_manager.insert_ip_analysis(
            ip_id=ip_id,
            reverse_dns=ip_results.get("reverse_dns"),
            geolocation=ip_results.get("geolocation"),
            asn_info=ip_results.get("asn_info"),
            port_scan=ip_results.get("port_scan"),
            reputation=ip_results.get("reputation"),
            risk_score=ip_results["overall_risk"]["score"],
            risk_level=ip_results["overall_risk"]["level"],
            risk_factors=ip_results["overall_risk"]["indicators"]
        )
    
    return {
        "ip_id": ip_id,
        "analysis": ip_results
    }

# Fonction pour afficher le tableau de bord
def show_dashboard():
    # Reprenez votre code existant pour le tableau de bord
    # Mais intégrez les nouvelles statistiques d'analyse
    st.title("Tableau de Bord VirusScan")
    
    # Statistiques de base
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Analyses effectuées", db_manager.get_user_analysis_count(st.session_state.user['user_id']))
    
    with col2:
        st.metric("Menaces détectées", db_manager.get_user_threats_count(st.session_state.user['user_id']))
    
    with col3:
        quota_used = st.session_state.user['quota_used']
        quota_limit = st.session_state.user['quota_limit']
        quota_percent = (quota_used / quota_limit) * 100
        st.metric("Quota utilisé", f"{quota_percent:.1f}%")
    
    # Analyses récentes
    st.subheader("Analyses récentes")
    recent_analyses = db_manager.get_recent_analyses(st.session_state.user['user_id'])
    
    if recent_analyses:
        st.table(recent_analyses)
    else:
        st.info("Aucune analyse récente.")

# Fonction pour afficher la page d'analyse de fichier
def show_file_analysis():
    st.title("Analyse de Fichier")
    
    # Uploader un fichier
    uploaded_file = st.file_uploader("Choisissez un fichier à analyser", type=None)
    
    sandbox_enabled = st.checkbox("Activer l'analyse comportementale (sandbox)")
    
    if uploaded_file is not None:
        # Afficher les informations de base sur le fichier
        st.write(f"Fichier: {uploaded_file.name} ({uploaded_file.size} octets)")
        
        # Sauvegarder le fichier temporairement
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, uploaded_file.name)
        
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Lancer l'analyse
        if st.button("Analyser le fichier"):
            with st.spinner("Analyse en cours..."):
                start_time = time.time()
                results = analyze_file(temp_file_path, st.session_state.user['user_id'], sandbox_enabled)
                end_time = time.time()
            
            st.success(f"Analyse terminée en {end_time - start_time:.2f} secondes!")
            
            # Afficher les résultats
            st.header("Résultats de l'analyse")
            
            # Informations de base
            st.subheader("Informations de base")
            st.json(results["static_analysis"]["basic_info"])
            
            # Hashes
            st.subheader("Empreintes cryptographiques")
            for hash_type, hash_value in results["static_analysis"]["hashes"].items():
                st.code(f"{hash_type.upper()}: {hash_value}")
            
            # Correspondances de signatures
            if results["signature_matches"]:
                st.subheader("Signatures détectées")
                st.error("⚠️ Ce fichier correspond à des signatures de malware connues!")
                
                for match in results["signature_matches"]:
                    st.write(f"**Type de hash:** {match['type']}")
                    st.json(match["match"])
            
            # Résultats d'analyse statique
            st.subheader("Analyse statique")
            
            # Format spécifique
            if results["static_analysis"]["format_specific"]:
                st.write("**Analyse spécifique au format:**")
                for format_type, format_data in results["static_analysis"]["format_specific"].items():
                    st.write(f"**Type:** {format_type}")
                    st.json(format_data)
            
            # Extraction de chaînes
            st.write("**Chaînes extraites:**")
            with st.expander("Afficher les chaînes extraites"):
                st.json(results["static_analysis"]["strings"])
            
            # Correspondances YARA
            st.write("**Correspondances YARA:**")
            st.json(results["static_analysis"]["yara_matches"])
            
            # Analyse sandbox si activée
            if sandbox_enabled and results["sandbox_analysis"]:
                st.subheader("Analyse comportementale (Sandbox)")
                
                # Processus créés
                st.write("**Processus créés:**")
                if results["sandbox_analysis"]["processes"]:
                    for process in results["sandbox_analysis"]["processes"]:
                        st.write(f"- {process.get('name')} (PID: {process.get('pid')})")
                else:
                    st.write("Aucun processus créé.")
                
                # Connexions réseau
                st.write("**Connexions réseau:**")
                if results["sandbox_analysis"]["network"]:
                    for conn in results["sandbox_analysis"]["network"]:
                        st.write(f"- {conn.get('local_address')} → {conn.get('remote_address')} ({conn.get('status')})")
                else:
                    st.write("Aucune connexion réseau détectée.")
                
                # Résumé du comportement
                st.write("**Résumé du comportement:**")
                st.json(results["sandbox_analysis"]["behavior_summary"])
            
            # Évaluation du risque
            st.subheader("Évaluation du risque")
            
            risk_level = results["static_analysis"]["risk_assessment"]["level"]
            risk_color = {
                "Faible": "green",
                "Moyen": "orange",
                "Élevé": "red",
                "Critique": "darkred"
            }.get(risk_level, "gray")
            
            st.markdown(f"<h3 style='color: {risk_color};'>Niveau de risque: {risk_level}</h3>", unsafe_allow_html=True)
            st.write(f"**Score de risque:** {results['static_analysis']['risk_assessment']['score']}")
            
            st.write("**Facteurs de risque:**")
            for factor in results["static_analysis"]["risk_assessment"]["factors"]:
                st.write(f"- {factor}")
            
            # Nettoyage
            try:
                os.remove(temp_file_path)
                os.rmdir(temp_dir)
            except:
                pass

# Fonction pour afficher la page d'analyse d'URL
def show_url_analysis():
    st.title("Analyse d'URL")
    
    url = st.text_input("Entrez l'URL à analyser")
    
    if url:
        if st.button("Analyser l'URL"):
            with st.spinner("Analyse en cours..."):
                start_time = time.time()
                results = analyze_url(url, st.session_state.user['user_id'])
                end_time = time.time()
            
            st.success(f"Analyse terminée en {end_time - start_time:.2f} secondes!")
            
            # Afficher les résultats
            st.header("Résultats de l'analyse")
            
            analysis = results["analysis"]
            
            # Structure de l'URL
            st.subheader("Structure de l'URL")
            st.json(analysis["url_analysis"])
            
            # Analyse DNS
            st.subheader("Analyse DNS")
            st.json(analysis["dns_analysis"])
            
            # Certificat SSL/TLS
            if analysis.get("certificate_analysis"):
                st.subheader("Certificat SSL/TLS")
                st.json(analysis["certificate_analysis"])
            
            # Analyse du contenu
            if analysis.get("content_analysis"):
                st.subheader("Analyse du contenu")
                with st.expander("Afficher l'analyse du contenu"):
                    content = analysis["content_analysis"]
                    
                    st.write(f"**Code de statut:** {content.get('status_code')}")
                    st.write(f"**URL finale:** {content.get('final_url')}")
                    
                    if content.get("redirected"):
                        st.write("**Historique de redirection:**")
                        for redirect in content.get("redirect_history", []):
                            st.write(f"- {redirect}")
                    
                    if content.get("forms"):
                        st.write("**Formulaires détectés:**")
                        for form in content.get("forms", []):
                            st.write(f"- Action: {form.get('action')}, Méthode: {form.get('method')}")
                            st.write(f"  Champs: {len(form.get('inputs', []))}, Mot de passe: {'Oui' if any(input.get('is_password') for input in form.get('inputs', [])) else 'Non'}")
            
            # Analyse de phishing
            if analysis.get("phishing_analysis"):
                st.subheader("Analyse de phishing")
                phishing = analysis["phishing_analysis"]
                
                if phishing.get("is_phishing"):
                    st.error(f"⚠️ Cette URL est probablement un site de phishing! (Confiance: {phishing.get('confidence_score')}%)")
                else:
                    st.info(f"Cette URL ne semble pas être un site de phishing. (Confiance: {phishing.get('confidence_score')}%)")
                
                st.write("**Indicateurs de phishing:**")
                for indicator in phishing.get("indicators", []):
                    st.write(f"- {indicator}")
            
            # Analyse de malware
            if analysis.get("malware_analysis"):
                st.subheader("Analyse de malware")
                malware = analysis["malware_analysis"]
                
                if malware.get("is_malicious"):
                    st.error(f"⚠️ Cette URL contient probablement du code malveillant! (Confiance: {malware.get('confidence_score')}%)")
                else:
                    st.info(f"Cette URL ne semble pas contenir de code malveillant. (Confiance: {malware.get('confidence_score')}%)")
                
                st.write("**Indicateurs de malware:**")
                for indicator in malware.get("indicators", []):
                    st.write(f"- {indicator}")
            
            # Évaluation du risque
            st.subheader("Évaluation du risque")
            
            risk_level = analysis["overall_risk"]["level"]
            risk_color = {
                "Faible": "green",
                "Moyen": "orange",
                "Élevé": "red",
                "Critique": "darkred"
            }.get(risk_level, "gray")
            
            st.markdown(f"<h3 style='color: {risk_color};'>Niveau de risque: {risk_level}</h3>", unsafe_allow_html=True)
            st.write(f"**Score de risque:** {analysis['overall_risk']['score']}")
            
            st.write("**Facteurs de risque:**")
            for factor in analysis["overall_risk"]["indicators"]:
                st.write(f"- {factor}")

# Fonction pour afficher la page d'analyse d'IP
def show_ip_analysis():
    st.title("Analyse d'Adresse IP")
    
    ip_address = st.text_input("Entrez l'adresse IP à analyser")
    
    if ip_address:
        if st.button("Analyser l'IP"):
            with st.spinner("Analyse en cours..."):
                start_time = time.time()
                results = analyze_ip(ip_address, st.session_state.user['user_id'])
                end_time = time.time()
            
            st.success(f"Analyse terminée en {end_time - start_time:.2f} secondes!")
            
            # Afficher les résultats
            st.header("Résultats de l'analyse")
            
            analysis = results["analysis"]
            
            # Informations de base
            st.subheader("Informations de base")
            st.json(analysis["basic_info"])
            
            # DNS inverse
            st.subheader("DNS Inverse")
            if analysis.get("reverse_dns"):
                st.write(f"**Nom d'hôte:** {analysis['reverse_dns']}")
            else:
                st.write("Aucune information DNS inverse disponible.")
            
            # Géolocalisation
            if analysis.get("geolocation"):
                st.subheader("Géolocalisation")
                geo = analysis["geolocation"]
                
                if not geo.get("error"):
                    st.write(f"**Pays:** {geo.get('country')} ({geo.get('country_code')})")
                    st.write(f"**Ville:** {geo.get('city')}")
                    st.write(f"**Région:** {geo.get('region')}")
                    st.write(f"**Coordonnées:** {geo.get('latitude')}, {geo.get('longitude')}")
                else:
                    st.write("Erreur de géolocalisation: " + geo.get("error"))
            
            # Information ASN
            if analysis.get("asn_info"):
                st.subheader("Information ASN")
                asn = analysis["asn_info"]
                
                if not asn.get("error"):
                    st.write(f"**ASN:** {asn.get('asn')}")
                    st.write(f"**Nom:** {asn.get('name')}")
                    st.write(f"**Route:** {asn.get('route')}")
                    st.write(f"**Type:** {asn.get('type')}")
                else:
                    st.write("Erreur d'information ASN: " + asn.get("error"))
            
            # Scan de ports
            if analysis.get("port_scan"):
                st.subheader("Scan de ports")
                port_scan = analysis["port_scan"]
                
                st.write(f"**Ports ouverts:** {port_scan.get('open_ports_count')}")
                
                open_ports = [port for port, info in port_scan.get("ports", {}).items() if info.get("open")]
                
                if open_ports:
                    st.write("**Liste des ports ouverts:**")
                    for port in open_ports:
                        service = port_scan["ports"][port].get("service", "Inconnu")
                        st.write(f"- Port {port}: {service}")
                else:
                    st.write("Aucun port ouvert détecté.")
            
            # Réputation
            if analysis.get("reputation"):
                st.subheader("Réputation")
                rep = analysis["reputation"]
                
                if rep.get("malicious"):
                    st.error("⚠️ Cette adresse IP est signalée comme malveillante!")
                elif rep.get("suspicious"):
                    st.warning("⚠️ Cette adresse IP est signalée comme suspecte!")
                else:
                    st.info("Aucune information négative connue pour cette adresse IP.")
                
                st.write(f"**Score de réputation:** {rep.get('score')}")
                
                if rep.get("is_proxy"):
                    st.write("⚠️ Cette adresse IP est un proxy connu.")
                
                if rep.get("is_tor_exit"):
                    st.write("⚠️ Cette adresse IP est un nœud de sortie TOR.")
                
                if rep.get("is_scanner"):
                    st.write("⚠️ Cette adresse IP est connue pour des activités de scan.")
                
                if rep.get("categories"):
                    st.write("**Catégories:**")
                    for category in rep.get("categories", []):
                        st.write(f"- {category}")
                
                if rep.get("sources"):
                    st.write("**Sources:**")
                    for source in rep.get("sources", []):
                        st.write(f"- {source}")
            
            # Évaluation du risque
            st.subheader("Évaluation du risque")
            
            risk_level = analysis["overall_risk"]["level"]
            risk_color = {
                "Faible": "green",
                "Moyen": "orange",
                "Élevé": "red",
                "Critique": "darkred"
           }.get(risk_level, "gray")
           
            st.markdown(f"<h3 style='color: {risk_color};'>Niveau de risque: {risk_level}</h3>", unsafe_allow_html=True)
            st.write(f"**Score de risque:** {analysis['overall_risk']['score']}")
           
            st.write("**Facteurs de risque:**")
            for factor in analysis["overall_risk"]["indicators"]:
               st.write(f"- {factor}")

# Programme principal
def main():
   # Initialisation des états de session
   if 'page' not in st.session_state:
       st.session_state.page = 'login'
   if 'logged_in' not in st.session_state:
       st.session_state.logged_in = False
   if 'user' not in st.session_state:
       st.session_state.user = None
   if 'current_page' not in st.session_state:
       st.session_state.current_page = "dashboard"

   # Appliquer le style personnalisé
   apply_custom_style()
   
   # Afficher la page appropriée
   if st.session_state.logged_in:
       # Barre latérale pour la navigation
       with st.sidebar:
           st.title("VirusScan")
           st.markdown("---")
           
           # Boutons de navigation
           if st.button(label="Tableau de bord", key="nav_dashboard", use_container_width=True):
               st.session_state.current_page = "dashboard"
               st.rerun()
           
           if st.button(label="Analyser un fichier 📄", key="nav_file", use_container_width=True):
               st.session_state.current_page = "analyser_fichier"
               st.rerun()
           
           if st.button(label="Scanner une URL 🌐", key="nav_url", use_container_width=True):
               st.session_state.current_page = "scanner_url"
               st.rerun()
           
           if st.button(label="🔎 Vérifier une adresse IP", key="nav_ip", use_container_width=True):
               st.session_state.current_page = "verifier_ip"
               st.rerun()
           
           if st.button(label="Mes analyses", key="nav_analyses", use_container_width=True):
               st.session_state.current_page = "analyses"
               st.rerun()
           
           if st.button(label="Statistiques", key="nav_stats", use_container_width=True):
               st.session_state.current_page = "statistiques"
               st.rerun()
           
           st.markdown("---")
           
           # Bouton de déconnexion
           if st.button(label="Se déconnecter", key="nav_logout"):
               st.session_state.logged_in = False
               st.session_state.user = None
               st.session_state.page = 'login'
               st.rerun()
           
           st.markdown("---")
           
           # Afficher un indicateur visuel de la page active
           st.caption(f"**Page active:** {st.session_state.current_page}")
       
       # Contenu principal
       if st.session_state.current_page == "dashboard":
           show_dashboard()
       elif st.session_state.current_page == "analyser_fichier":
           show_file_analysis()
       elif st.session_state.current_page == "scanner_url":
           show_url_analysis()
       elif st.session_state.current_page == "verifier_ip":
           show_ip_analysis()
       elif st.session_state.current_page == "analyses":
           show_analyses()
       elif st.session_state.current_page == "statistiques":
           show_statistiques()
   
   else:
       # Utilisez vos fonctions existantes d'authentification
       if st.session_state.page == 'login':
           show_login_page()
       else:
           show_signup_page()

# Fonction pour afficher les analyses (à adapter selon votre code existant)
def show_analyses():
   st.title("Mes analyses")
   
   # Onglets pour différents types d'analyses
   tab1, tab2, tab3 = st.tabs(["Fichiers", "URLs", "IPs"])
   
   with tab1:
       st.header("Analyses de fichiers")
       file_analyses = db_manager.get_user_file_analyses(st.session_state.user['user_id'])
       
       if file_analyses:
           st.dataframe(file_analyses)
       else:
           st.info("Aucune analyse de fichier trouvée.")
   
   with tab2:
       st.header("Analyses d'URLs")
       url_analyses = db_manager.get_user_url_analyses(st.session_state.user['user_id'])
       
       if url_analyses:
           st.dataframe(url_analyses)
       else:
           st.info("Aucune analyse d'URL trouvée.")
   
   with tab3:
       st.header("Analyses d'IPs")
       ip_analyses = db_manager.get_user_ip_analyses(st.session_state.user['user_id'])
       
       if ip_analyses:
           st.dataframe(ip_analyses)
       else:
           st.info("Aucune analyse d'IP trouvée.")

# Fonction pour afficher les statistiques (à adapter selon votre code existant)
def show_statistiques():
   st.title("Statistiques")
   
   # Obtenir les données des analyses
   file_count = db_manager.get_user_file_count(st.session_state.user['user_id'])
   url_count = db_manager.get_user_url_count(st.session_state.user['user_id'])
   ip_count = db_manager.get_user_ip_count(st.session_state.user['user_id'])
   
   risk_levels = db_manager.get_user_risk_levels(st.session_state.user['user_id'])
   
   # Afficher les statistiques
   col1, col2 = st.columns(2)
   
   with col1:
       st.subheader("Répartition par type")
       types_data = {
           "Fichiers": file_count,
           "URLs": url_count,
           "IPs": ip_count
       }
       st.bar_chart(types_data)
   
   with col2:
       st.subheader("Répartition par niveau de risque")
       risk_data = {
           "Faible": risk_levels.get("Faible", 0),
           "Moyen": risk_levels.get("Moyen", 0),
           "Élevé": risk_levels.get("Élevé", 0),
           "Critique": risk_levels.get("Critique", 0)
       }
       st.bar_chart(risk_data)
   
   # Analyses dans le temps
   st.subheader("Analyses dans le temps")
   time_data = db_manager.get_user_analyses_over_time(st.session_state.user['user_id'])
   
   if time_data:
       st.line_chart(time_data)
   else:
       st.info("Pas assez de données pour afficher l'évolution temporelle.")

if __name__ == "__main__":
   main()