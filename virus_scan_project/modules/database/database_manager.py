# modules/database/db_manager.py
import psycopg2
import psycopg2.extras
import json
from datetime import datetime, timedelta
import pandas as pd

class DatabaseManager:
    def __init__(self, db_config=None):
        """
        Initialise le gestionnaire de base de données.
        
        Args:
            db_config: Configuration de la base de données
        """
        # Configuration par défaut
        self.db_config = db_config or {
            'host': 'localhost',
            'dbname': 'VirusScan',
            'user': 'your_username',
            'password': 'your_password',
            'port': 5432
        }
    
    def get_connection(self):
        """Établit une connexion à la base de données."""
        try:
            conn = psycopg2.connect(**self.db_config)
            return conn
        except Exception as e:
            print(f"Erreur de connexion à la base de données: {e}")
            return None
    
    # Méthodes pour les fichiers
    
    def insert_file(self, hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type, submitter_id):
        """Insère un nouveau fichier dans la base de données"""
        conn = self.get_connection()
        if not conn:
            return None
        
        cursor = None
        try:
            current_time = datetime.now()
            
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Vérifier si le fichier existe déjà
                cursor.execute("SELECT file_id FROM files WHERE hash_sha256 = %s", (hash_sha256,))
                existing_file = cursor.fetchone()
                
                if existing_file:
                    # Mettre à jour la date de dernière observation
                    cursor.execute(
                        "UPDATE files SET last_seen_date = %s WHERE file_id = %s RETURNING file_id",
                        (current_time, existing_file['file_id'])
                    )
                    file_id = cursor.fetchone()[0]
                else:
                    # Insérer un nouveau fichier
                    cursor.execute(
                        """
                        INSERT INTO files 
                        (hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type, 
                        first_seen_date, last_seen_date, submitter_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING file_id
                        """,
                        (hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type,
                        current_time, current_time, submitter_id)
                    )
                    file_id = cursor.fetchone()[0]
                
                conn.commit()
                return file_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion du fichier: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def insert_static_analysis(self, file_id, mime_type, analysis_result, risk_score, risk_level, risk_factors):
        """Insère les résultats d'analyse statique"""
        conn = self.get_connection()
        if not conn:
            return False
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO file_static_analyses 
                    (file_id, analysis_date, mime_type, analysis_result, risk_score, risk_level, risk_factors)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING analysis_id
                    """,
                    (file_id, datetime.now(), mime_type, json.dumps(analysis_result), 
                    risk_score, risk_level, json.dumps(risk_factors))
                )
                
                analysis_id = cursor.fetchone()[0]
                conn.commit()
                return analysis_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'analyse statique: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def insert_sandbox_analysis(self, file_id, execution_success, execution_output, processes_created, 
                                file_operations, network_connections, analysis_result, 
                                risk_score, risk_level, risk_factors):
        """Insère les résultats d'analyse sandbox"""
        conn = self.get_connection()
        if not conn:
            return False
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO file_sandbox_analyses 
                    (file_id, analysis_date, execution_success, execution_output, processes_created, 
                    file_operations, network_connections, analysis_result, risk_score, risk_level, risk_factors)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING analysis_id
                    """,
                    (file_id, datetime.now(), execution_success, execution_output, 
                    json.dumps(processes_created), json.dumps(file_operations), 
                    json.dumps(network_connections), json.dumps(analysis_result),
                    risk_score, risk_level, json.dumps(risk_factors))
                )
                
                analysis_id = cursor.fetchone()[0]
                conn.commit()
                return analysis_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'analyse sandbox: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # Méthodes pour les URLs
    
    def insert_url(self, url, domain, path, scheme, submitter_id):
        """Insère une nouvelle URL dans la base de données"""
        conn = self.get_connection()
        if not conn:
            return None
        
        cursor = None
        try:
            current_time = datetime.now()
            
            # Calculer le hash de l'URL pour l'unicité
            url_hash = hash(url)
            
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Vérifier si l'URL existe déjà
                cursor.execute("SELECT url_id FROM urls WHERE url_hash = %s", (url_hash,))
                existing_url = cursor.fetchone()
                
                if existing_url:
                    # Mettre à jour la date de dernière observation
                    cursor.execute(
                        "UPDATE urls SET last_seen_date = %s WHERE url_id = %s RETURNING url_id",
                        (current_time, existing_url['url_id'])
                    )
                    url_id = cursor.fetchone()[0]
                else:
                    # Insérer une nouvelle URL
                    cursor.execute(
                        """
                        INSERT INTO urls 
                        (url, url_hash, domain, path, scheme, submit_date, first_seen_date, last_seen_date, submitter_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING url_id
                        """,
                        (url, url_hash, domain, path, scheme, current_time, current_time, current_time, submitter_id)
                    )
                    url_id = cursor.fetchone()[0]
                
                conn.commit()
                return url_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'URL: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def insert_url_analysis(self, url_id, url_structure, dns_info, certificate_info, content_info,
                            phishing_analysis, malware_analysis, risk_score, risk_level, risk_factors):
        """Insère les résultats d'analyse d'URL"""
        conn = self.get_connection()
        if not conn:
            return False
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO url_detailed_analyses 
                    (url_id, analysis_date, url_structure, dns_info, certificate_info, 
                    content_info, phishing_analysis, malware_analysis, risk_score, risk_level, risk_factors)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING analysis_id
                    """,
                    (url_id, datetime.now(), json.dumps(url_structure), json.dumps(dns_info), 
                    json.dumps(certificate_info) if certificate_info else None, 
                    json.dumps(content_info) if content_info else None,
                    json.dumps(phishing_analysis) if phishing_analysis else None, 
                    json.dumps(malware_analysis) if malware_analysis else None,
                    risk_score, risk_level, json.dumps(risk_factors))
                )
                
                analysis_id = cursor.fetchone()[0]
                conn.commit()
                return analysis_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'analyse d'URL: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # Méthodes pour les IPs
    
    def insert_ip(self, ip_address, ip_version, submitter_id):
        """Insère une nouvelle adresse IP dans la base de données"""
        conn = self.get_connection()
        if not conn:
            return None
        
        cursor = None
        try:
            current_time = datetime.now()
            
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Vérifier si l'IP existe déjà
                cursor.execute("SELECT ip_id FROM ip_addresses WHERE ip_address = %s", (ip_address,))
                existing_ip = cursor.fetchone()
                
                if existing_ip:
                    # Mettre à jour la date de dernière observation
                    cursor.execute(
                        "UPDATE ip_addresses SET last_seen_date = %s WHERE ip_id = %s RETURNING ip_id",
                        (current_time, existing_ip['ip_id'])
                    )
                    ip_id = cursor.fetchone()[0]
                else:
                    # Insérer une nouvelle IP
                    cursor.execute(
                        """
                        INSERT INTO ip_addresses 
                        (ip_address, ip_version, first_seen_date, last_seen_date, submit_date, submitter_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING ip_id
                        """,
                        (ip_address, ip_version, current_time, current_time, current_time, submitter_id)
                    )
                    ip_id = cursor.fetchone()[0]
                
                conn.commit()
                return ip_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'IP: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def insert_ip_analysis(self, ip_id, reverse_dns, geolocation, asn_info, port_scan, 
                           reputation, risk_score, risk_level, risk_factors):
        """Insère les résultats d'analyse d'IP"""
        conn = self.get_connection()
        if not conn:
            return False
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO ip_detailed_analyses 
                    (ip_id, analysis_date, reverse_dns, geolocation, asn_info, 
                    port_scan, reputation, risk_score, risk_level, risk_factors)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING analysis_id
                    """,
                    (ip_id, datetime.now(), reverse_dns, 
                    json.dumps(geolocation) if geolocation else None, 
                    json.dumps(asn_info) if asn_info else None,
                    json.dumps(port_scan) if port_scan else None, 
                    json.dumps(reputation) if reputation else None,
                    risk_score, risk_level, json.dumps(risk_factors))
                )
                
                analysis_id = cursor.fetchone()[0]
                conn.commit()
                return analysis_id
                
        except Exception as e:
            print(f"Erreur lors de l'insertion de l'analyse d'IP: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # Méthodes pour les requêtes d'analyses
    
    def get_user_analysis_count(self, user_id):
        """Obtient le nombre total d'analyses effectuées par un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return 0
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM analysis_results_view 
                    WHERE submitter = (SELECT username FROM users WHERE user_id = %s)
                    """,
                    (user_id,)
                )
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Erreur lors de l'obtention du nombre d'analyses: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_threats_count(self, user_id):
        """Obtient le nombre de menaces détectées pour un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return 0
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM analysis_results_view 
                    WHERE submitter = (SELECT username FROM users WHERE user_id = %s)
                    AND risk_level IN ('Élevé', 'Critique')
                    """,
                    (user_id,)
                )
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Erreur lors de l'obtention du nombre de menaces: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_recent_analyses(self, user_id, limit=5):
        """Obtient les analyses récentes d'un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return []
        
        cursor = None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT entity_type, entity_name, submission_date, risk_level
                    FROM analysis_results_view 
                    WHERE submitter = (SELECT username FROM users WHERE user_id = %s)
                    ORDER BY submission_date DESC
                    LIMIT %s
                    """,
                    (user_id, limit)
                )
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            print(f"Erreur lors de l'obtention des analyses récentes: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_file_analyses(self, user_id):
        """Obtient les analyses de fichiers d'un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return []
        
        cursor = None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT f.file_name, f.file_type, f.upload_date, 
                           f.hash_sha256, fsa.risk_level, fsa.risk_score
                    FROM files f
                    JOIN file_static_analyses fsa ON f.file_id = fsa.file_id
                    WHERE f.submitter_id = %s
                    ORDER BY f.upload_date DESC
                    """,
                    (user_id,)
                )
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            print(f"Erreur lors de l'obtention des analyses de fichiers: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_url_analyses(self, user_id):
        """Obtient les analyses d'URLs d'un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return []
        
        cursor = None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT u.url, u.domain, u.submit_date, 
                           uda.risk_level, uda.risk_score
                    FROM urls u
                    JOIN url_detailed_analyses uda ON u.url_id = uda.url_id
                    WHERE u.submitter_id = %s
                    ORDER BY u.submit_date DESC
                    """,
                    (user_id,)
                )
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            print(f"Erreur lors de l'obtention des analyses d'URLs: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_ip_analyses(self, user_id):
        """Obtient les analyses d'IPs d'un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return []
        
        cursor = None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT ip.ip_address, ip.ip_version, ip.submit_date, 
                           ida.reverse_dns, ida.risk_level, ida.risk_score
                    FROM ip_addresses ip
                    JOIN ip_detailed_analyses ida ON ip.ip_id = ida.ip_id
                    WHERE ip.submitter_id = %s
                    ORDER BY ip.submit_date DESC
                    """,
                    (user_id,)
                )
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            print(f"Erreur lors de l'obtention des analyses d'IPs: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # Méthodes pour les statistiques
    
    def get_user_file_count(self, user_id):
        """Obtient le nombre de fichiers analysés par un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return 0
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM files WHERE submitter_id = %s",
                    (user_id,)
                )
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Erreur lors de l'obtention du nombre de fichiers: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_url_count(self, user_id):
        """Obtient le nombre d'URLs analysées par un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return 0
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM urls WHERE submitter_id = %s",
                    (user_id,)
                )
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Erreur lors de l'obtention du nombre d'URLs: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_ip_count(self, user_id):
        """Obtient le nombre d'IPs analysées par un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return 0
        
        cursor = None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM ip_addresses WHERE submitter_id = %s",
                    (user_id,)
                )
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Erreur lors de l'obtention du nombre d'IPs: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_user_risk_levels(self, user_id):
        """Obtient la répartition des niveaux de risque pour un utilisateur"""
        conn = self.get_connection()
        if not conn:
            return {}
        
        cursor = None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT risk_level, COUNT(*) as count
                    FROM analysis_results_view 
                    WHERE submitter = (SELECT username FROM users WHERE user_id = %s)
                    GROUP BY risk_level
                    """,
                    (user_id,)
                )
                
                results = cursor.fetchall()
                return {row['risk_level']: row['count'] for row in results}
                
        except Exception as e:
            print(f"Erreur lors de l'obtention des niveaux de risque: {e}")
            return {}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
# modules/database/db_manager.py (suite)
    def get_user_analyses_over_time(self, user_id, days=30):
       """Obtient les analyses d'un utilisateur sur une période de temps"""
       conn = self.get_connection()
       if not conn:
           return None
       
       cursor = None
       try:
           # Calculer la date de début
           start_date = datetime.now() - timedelta(days=days)
           
           with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
               cursor.execute(
                   """
                   SELECT DATE(submission_date) as date, COUNT(*) as count
                   FROM analysis_results_view 
                   WHERE submitter = (SELECT username FROM users WHERE user_id = %s)
                   AND submission_date >= %s
                   GROUP BY DATE(submission_date)
                   ORDER BY DATE(submission_date)
                   """,
                   (user_id, start_date)
               )
               
               results = cursor.fetchall()
               
               # Convertir en DataFrame pour faciliter la visualisation avec Streamlit
               if results:
                   df = pd.DataFrame(results)
                   df.set_index('date', inplace=True)
                   return df
               
               return None
               
       except Exception as e:
           print(f"Erreur lors de l'obtention des analyses temporelles: {e}")
           return None
       finally:
           if cursor:
               cursor.close()
           if conn:
               conn.close()