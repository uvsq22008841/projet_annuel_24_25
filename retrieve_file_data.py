import ipaddress
import streamlit as st
import psycopg2
import psycopg2.extras
import bcrypt
import uuid
import hashlib,os,mimetypes
import datetime
import re # regex
from urllib.parse import urlparse
import validators
import pandas as pd
import os, uuid, ssl
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
# Désactiver la vérification du certificat (à utiliser uniquement en développement)
# Option 1: Définir une variable d'environnement
os.environ['AZURE_STORAGE_DISABLE_HTTPS'] = 'true'

# Option 2: Utiliser un contexte SSL personnalisé
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Configuration pour le cloud azure 
def connection_azure_cloud() : 
    storage_connection_string = ""    # Créer le client avec désactivation de la vérification SSL
    blob_service_client = BlobServiceClient.from_connection_string(
        storage_connection_string,
        connection_verify=False  # Désactive la vérification du certificat
    )
    return blob_service_client


# Configuration de la base de données postgresql
DB_CONFIG = {
    'host': 'localhost',
    'dbname': 'VirusScan',
    'user': '',
    'password': '',
    'port':     1234567890
}

def get_db_connection():
    """Établit une connexion à la base de données."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        st.error(f"Erreur de connexion à la base de données: {e}")
        return None

def hash_password(password):
    """Hashe un mot de passe en utilisant bcrypt."""
    # Génère un sel et hashe le mot de passe
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')  # Convertir en string pour stockage

def verify_password(stored_hash, provided_password):
    """Vérifie si le mot de passe fourni correspond au hash stocké."""
    stored_hash_bytes = stored_hash.encode('utf-8')
    provided_password_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

def generate_api_key():
    """Génère une clé API unique."""
    return str(uuid.uuid4())

def check_email_exists(email):
    """Vérifie si un email existe déjà dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        return cursor.fetchone() is not None
    except Exception as e:
        st.error(f"Erreur lors de la vérification de l'email: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        conn.close()

def check_username_exists(username):
    """Vérifie si un nom d'utilisateur existe déjà dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        return cursor.fetchone() is not None
    except Exception as e:
        st.error(f"Erreur lors de la vérification du nom d'utilisateur: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        conn.close()

def create_user(username, email, password, quota_limit=100, is_admin=False):
    """Crée un nouvel utilisateur dans la base de données."""
    # Vérifier si l'email existe déjà
    if check_email_exists(email):
        return None, "Cet email est déjà utilisé"
    elif check_username_exists(username):
        return None, "Ce nom d'utilisateur est déjà utilisé"
    
    # Hasher le mot de passe
    password_hash = hash_password(password)
    
    # Générer une clé API unique
    api_key = generate_api_key()
    
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            # Insérer le nouvel utilisateur
            cursor.execute("SELECT setval('users_user_id_seq', (SELECT MAX(user_id) FROM users))")
            # Insérer le nouvel utilisateur en utilisant les paramètres passés à la fonction
            insert_script = '''
                INSERT INTO users 
                (username, email, password_hash, api_key, quota_limit, is_admin) 
                VALUES (%s, %s, %s, %s, %s, %s) 
                RETURNING user_id
            '''
            insert_values = (str(username), str(email), str(password_hash), str(api_key), quota_limit, is_admin)
            cursor.execute(insert_script, insert_values)
            
            # Récupérer l'ID attribué
            new_user_id = cursor.fetchone()[0]
            print(new_user_id)
            conn.commit()
            return new_user_id, None
    except Exception as e:
        conn.rollback()
        return None, f"Erreur lors de la création de l'utilisateur: {e}"
    finally:
        if cursor:
            cursor.close()
        conn.close()
        
        
def authenticate_user(email, password):
    """Authentifie un utilisateur par email et mot de passe."""
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Rechercher l'utilisateur par email
        cursor.execute("""
            SELECT *
            FROM users 
            WHERE email = %s
        """, (email,))
        
        user = cursor.fetchone()
        print(user)
        # Vérifier si l'utilisateur existe
        if not user:
            return None, "Email ou mot de passe incorrect"
        
        # Vérifier le mot de passe
        if not verify_password(user['password_hash'], password):
            return None, "Email ou mot de passe incorrect"
        
        # Mettre à jour la date de dernière connexion
        cursor.execute("""
            UPDATE users 
            SET last_login_date = %s 
            WHERE user_id = %s
        """, (datetime.datetime.now(), user['user_id']))
        
        conn.commit()
        
        # Retourner les informations de l'utilisateur
        return {
            'user_id': user['user_id'],
            'username': user['username'],
            'api_key' : user['api_key'],
            'quota_used' : user['quota_used'],
            'quota_limit' : user['quota_limit'],
            'is_admin': user['is_admin'],
        }, None
    except Exception as e:
        conn.rollback()
        return None, f"Erreur lors de l'authentification: {e}"
    finally:
        if cursor:
            cursor.close()
        conn.close()




#######################################  FILES  ###########################################################
def analyze_file(file_path):
    """
    Analyse un fichier et retourne son type, sa taille et ses hachages MD5, SHA-256 et SHA-1.
    Cette version utilise uniquement des bibliothèques standard Python et est compatible Windows.
    
    Args:
        file_path (str): Chemin vers le fichier à analyser
        
    Returns:
        dict: Dictionnaire contenant le type, la taille et les hachages du fichier
        
    Raises:
        FileNotFoundError: Si le fichier n'existe pas
        PermissionError: Si l'accès au fichier est refusé
    """
    
    # Vérifier que le fichier existe
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Le fichier '{file_path}' n'existe pas.")
    
    result = {}
    
    # Obtenir la taille du fichier
    file_size = os.path.getsize(file_path)
    
   
    # Obtenir les métadonnées du fichier
    file_stats = os.stat(file_path)
    
    # Déterminer le type de fichier basé sur l'extension
    mimetypes.init()
    file_type, encoding = mimetypes.guess_type(file_path)
    
    if file_type is None:
        # Essai avec quelques signatures de fichier binaires communes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)  # Lire les premiers octets
                
                if header.startswith(b'\x89PNG\r\n\x1a\n'):
                    file_type = 'image/png'
                elif header.startswith(b'\xff\xd8'):
                    file_type = 'image/jpeg'
                elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                    file_type = 'image/gif'
                elif header.startswith(b'%PDF'):
                    file_type = 'application/pdf'
                elif header.startswith(b'\x50\x4b\x03\x04'):
                    file_type = 'application/zip'
                elif header.startswith(b'MZ'):
                    file_type = 'application/x-msdownload'  # Executable Windows
                else:
                    file_type = 'application/octet-stream'  # Type par défaut
        except:
            file_type = 'unknown/unknown'
    
    result['mime_type'] = file_type
    result['file_extension'] = os.path.splitext(file_path)[1]
    result['size_bigint'] = file_size
    # Calculer les hachages
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as file:
            # Lire le fichier par blocs pour gérer les fichiers volumineux
            for chunk in iter(lambda: file.read(4096), b''):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
        result['hashes'] = {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    except PermissionError:
        raise PermissionError(f"Accès refusé au fichier '{file_path}'.")
    except Exception as e:
        result['hashes'] = {
            'md5': f"Erreur: {str(e)}",
            'sha1': f"Erreur: {str(e)}",
            'sha256': f"Erreur: {str(e)}"
        }
    print(result['hashes'])
    print(result)
    return result



def insert_file(hash_md5:dict, hash_sha1, hash_sha256, file_name, file_size, file_type, submitter_id, first_seen_date=None, last_seen_date=None):
    """
    Insère un nouveau fichier dans la base de données.
    
    CREATE TABLE files (
        file_id SERIAL PRIMARY KEY,
        hash_md5 VARCHAR(32) NOT NULL,
        hash_sha1 VARCHAR(40) NOT NULL,
        hash_sha256 VARCHAR(64) NOT NULL UNIQUE,
        file_name VARCHAR(255),
        file_size BIGINT NOT NULL,
        file_type VARCHAR(100),
        upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        first_seen_date TIMESTAMP NOT NULL,
        last_seen_date TIMESTAMP NOT NULL,
        submitter_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE
    );
    
    Paramètres:
    - hash_md5: Hash MD5 du fichier
    - hash_sha1: Hash SHA-1 du fichier
    - hash_sha256: Hash SHA-256 du fichier (doit être unique)
    - file_name: Nom du fichier
    - file_size: Taille du fichier en octets
    - file_type: Type MIME du fichier
    - submitter_id: ID de l'utilisateur qui soumet le fichier
    - first_seen_date: Date de première observation (défaut: date actuelle)
    - last_seen_date: Date de dernière observation (défaut: date actuelle)
    
    Retourne:
    - file_id: ID du nouveau fichier, ou None en cas d'erreur
    """
    cursor = None
    conn = None
    
    # Définir les dates par défaut si non fournies
    current_time = datetime.datetime.now()
    if first_seen_date is None:
        first_seen_date = current_time
    if last_seen_date is None:
        last_seen_date = current_time
    
    try:
        
        with psycopg2.connect(**DB_CONFIG) as conn :
        
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor :
                # Réinitialiser la séquence d'ID pour qu'elle commence après la plus grande valeur existante
                cursor.execute("SELECT setval('files_file_id_seq', (SELECT MAX(file_id) FROM files))")
                
                # Vérifier si un fichier avec le même hash SHA-256 existe déjà
                cursor.execute("SELECT file_id FROM files WHERE hash_sha256 = %s", (hash_sha256,))
                existing_file = cursor.fetchone()
                
                if existing_file:
                    # Si le fichier existe déjà, mettre à jour last_seen_date
                    cursor.execute(
                        "UPDATE files SET last_seen_date = %s WHERE file_id = %s RETURNING file_id",
                        (datetime.datetime.now(), existing_file[0])
                    )
                    file_id = cursor.fetchone()[0]
                    conn.commit()
                    print(f"Fichier existant mis à jour, ID: {file_id}")
                    return False, "Le fichier existe deja"
                
                # Sinon, insérer un nouveau fichier
                insert_script = """
                    INSERT INTO files 
                    (hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type, 
                    first_seen_date, last_seen_date, submitter_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING file_id
                """
                cursor.execute(insert_script, (
                    hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type,
                    first_seen_date, last_seen_date, submitter_id))
                print( hash_md5, hash_sha1, hash_sha256, file_name, file_size, file_type,
                    first_seen_date, last_seen_date, submitter_id)
                file_id = cursor.fetchone()[0]
                conn.commit()
                print(f"Nouveau fichier inséré, ID: {file_id}")
                return True
            
            
    except Exception as e:
        print(f"Erreur lors de l'insertion du fichier: {e}")
        if conn is not None:
            conn.rollback()
        return False
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None: 
            conn.close()


def retrieve_users_files(user_id):
    """Récupérer les fichiers uploadés dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
    
        # Récupérer tous les fichiers d'un utilisateur spécifique
        cursor.execute("""
            SELECT * FROM file_scan_view
            WHERE submitter_id = %s
            ORDER BY upload_date DESC
        """, (user_id,))
        
        # Récupérer tous les fichiers
        files = cursor.fetchall()
        
        # Vérifier si des fichiers ont été trouvés
        if not files or len(files) == 0:
            return [], "Aucun fichier trouvé dans la base de données."
        
        # Convertir les résultats en liste de dictionnaires
        files_list = []
        for file in files:
            files_list.append({
                'file_type': file['file_type'],
                'upload_date': file['upload_date'],
                'submitter_id': file['submitter_id'],
                'file_name': file['file_name'],
                'scan_status': file['scan_status'],
                'detection_status': file['detection_status']
            })
        
        # Retourne la liste complète des fichiers
        return files_list

    except Exception as e:
        conn.rollback()
        return None, f"Erreur lors de la récupération des fichiers: {e}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            
            
def retrieve_all_files():
    """Récupérer les fichiers uploadés dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer tous les fichiers de tous les utilisateurs
        cursor.execute("""
            SELECT * FROM file_scan_view
            ORDER BY upload_date DESC
        """)
       
        
        # Récupérer tous les fichiers
        files = cursor.fetchall()
        
        # Vérifier si des fichiers ont été trouvés
        if not files or len(files) == 0:
            return [], "Aucun fichier trouvé dans la base de données."
        
        # Convertir les résultats en liste de dictionnaires
        files_list = []
        for file in files:
            files_list.append({
                'file_type': file['file_type'],
                'upload_date': file['upload_date'],
                'submitter_id': file['submitter_id'],
                'file_name': file['file_name'],
                'scan_status': file['scan_status'],
                'detection_status': file['detection_status']
                
            })
        
        # Retourne la liste complète des fichiers
        return files_list

    except Exception as e:
        conn.rollback()
        return None, f"Erreur lors de la récupération des fichiers: {e}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
                  

def retrieve_users_urls(user_id):
    """Récupérer les URLs uploadés dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
    
        # Récupérer tous les fichiers d'un utilisateur spécifique
        cursor.execute("""
            SELECT * FROM file_scan_view
            WHERE submitter_id = %s
            ORDER BY upload_date DESC
        """, (user_id,))
        
        # Récupérer tous les fichiers
        files = cursor.fetchall()
        
        # Vérifier si des fichiers ont été trouvés
        if not files or len(files) == 0:
            return [], "Aucun fichier trouvé dans la base de données."
        
        # Convertir les résultats en liste de dictionnaires
        files_list = []
        for file in files:
            files_list.append({
                'file_type': file['file_type'],
                'upload_date': file['upload_date'],
                'submitter_id': file['submitter_id'],
                'file_name': file['file_name'],
                'scan_status': file['scan_status'],
                'detection_status': file['detection_status']
            })
        
        # Retourne la liste complète des fichiers
        return files_list

    except Exception as e:
        conn.rollback()
        return None, f"Erreur lors de la récupération des fichiers: {e}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            


# Functions for different pages
# def ():
#     st.subheader("Analyser un nouveau fichier")
#     uploaded_file = st.file_uploader(label="Choisissez un fichier à analyser", type=["exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "js", "html", "zip"])
#     if uploaded_file is not None:
#         st.write("Fichier reçu:", uploaded_file.name)
#         result = analyze_file(uploaded_file)
#         if st.button(label="Lancer l'analyse", key="launch_analysis_btn"):
#             # Creer un container à l'id de l'user
#             try:
#                 blob_service_client = connection_azure_cloud()
#                 container_name = f"user-{st.session_state.user['user_id']}"
#                 # Vérifier si le conteneur existe déjà
#                 container_client = blob_service_client.get_container_client(container_name)
#                 print(container_client)
#                 if container_client.exists():
#                     print(f"Le conteneur '{container_name}' existe déjà.")
#                 else:
#                     # Créer le conteneur s'il n'existe pas
#                     try:
#                         container_client = blob_service_client.create_container(container_name)
#                         print(f"Conteneur '{container_name}' créé avec succès!")
                        
#                         blob_obj = blob_service_client.get_blob_client(container=container_name,blob= uploaded_file.name)
#                         # blob_obj.upload_blob(name=uploaded_file, data=contents, overwrite=True)
#                         st.info("Upload du fichier...")
#                         st.info("Analyse en cours... (Simulation)")
#                         #st.success("Fichier analysé avec succès! Aucune menace détectée.")
                        
                        
#                     except Exception as e:
#                         print(e)
#             except Exception as e:
#                 print(f"Erreur: {e}")
                
#     else:
#         st.warning("Choisissez un fichier")


#####################################   URL   ############################################################################################
                
def show_scanner_url():
    """
    -	CREATE TABLE urls (
-	    url_id SERIAL PRIMARY KEY,
-	    url TEXT NOT NULL,
-	    url_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 de l'URL pour recherche rapide et unicité
-	    domain VARCHAR(255) NOT NULL,
-	    path TEXT,
-	    query_params TEXT,
-	    scheme VARCHAR(10) NOT NULL, -- http ou https
-	    submit_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
-	    first_seen_date TIMESTAMP NOT NULL,
-	    last_seen_date TIMESTAMP NOT NULL,
-	    submitter_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
-	    is_malicious BOOLEAN DEFAULT NULL -- NULL si non déterminé, TRUE/FALSE sinon
-	);

    """
    st.title("Scanner URL")
    url = st.text_input("Entrez l'URL à analyser", key="url_input")
    if st.button(label="Scanner", key="scan_url_btn"):
        if is_valid_url(url) ==  True:
            create_url(url)
            update_url_quota()
            st.info("Analyse en cours... (Simulation)")
            st.success("URL analysée avec succès! Aucune menace détectée.")
        else:
            st.warning("Entrez une URL valide exemple : https://google.com", icon="🚨")
        
def extract_domain(url):
    """
    Extrait le domaine d'une URL.
    
    Args:
        url (str): L'URL à analyser
        
    Returns:
        str: Le domaine de l'URL
    """
    try:
        # Ajouter le préfixe http:// si aucun schéma n'est présent
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        # Utiliser urlparse pour extraire le domaine
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Supprimer le port s'il est présent (exemple: example.com:8080)
        domain = domain.split(':')[0]
        
        return domain
    except Exception as e:
        print(f"Erreur lors de l'extraction du domaine: {e}")
        return None


def extract_path(url):
    """
    Extrait le chemin d'une URL.
    
    Args:
        url (str): L'URL à analyser
        
    Returns:
        str: Le chemin de l'URL
    """
    try:
        # Ajouter le préfixe http:// si aucun schéma n'est présent
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        # Utiliser urlparse pour extraire le chemin
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # Retourner '/' si le chemin est vide
        if not path:
            return '/'
            
        return path
    except Exception as e:
        print(f"Erreur lors de l'extraction du chemin: {e}")
        return None


def get_scheme(url):
    """
    Détermine si une URL utilise HTTP ou HTTPS.
    
    Args:
        url (str): L'URL à analyser
        
    Returns:
        str: 'http' ou 'https' selon le schéma de l'URL
             None si le schéma n'est pas reconnu ou en cas d'erreur
    """
    try:
        # Vérifier si l'URL commence par http:// ou https://
        if url.startswith('http://'):
            return 'http'
        elif url.startswith('https://'):
            return 'https'
        
        # Si l'URL n'a pas de schéma explicite, essayer de deviner
        # (Par exemple, example.com ou www.example.com)
        if re.match(r'^(www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+', url):
            return 'http'  # Par défaut, on suppose http
            
        return None
    except Exception as e:
        print(f"Erreur lors de la détermination du schéma: {e}")
        return None
    
       
def is_valid_url(url):
    # Regex pour vérifier uniquement les URL en HTTP ou HTTPS
    url_regex = re.compile(
        r'^(https?):\/\/'  # Uniquement http ou https
        r'([a-zA-Z0-9.-]+)'  # Nom de domaine
        r'(\.[a-zA-Z]{2,})'  # Extension (.com, .fr, etc.)
        r'(:\d+)?'  # Port optionnel (:80, :443...)
        r'(\/[^\s]*)?$',  # Chemin optionnel (/page, /index.html...)
        re.IGNORECASE
    )

    # Vérifie avec la regex et la librairie validators
    return bool(url_regex.match(url)) and validators.url(url)  


def update_url_quota():
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            print("user  ", str(st.session_state.user['user_id']))
            # Mettre à jour la date de dernière connexion
            cursor.execute("""select quota_used from users
                where user_id = %s """, (str(st.session_state.user['user_id']),))  # Note the comma inside parentheses to make it a tuple
            
            quota_used = cursor.fetchone()[0]
            print(quota_used)
            quota_used = quota_used+1
            cursor.execute("""
                UPDATE users 
                SET quota_used = %s 
                WHERE user_id = %s
            """, (quota_used, str(st.session_state.user['user_id'])))  # Use a tuple with parentheses
            
            conn.commit()
            st.write("aaaa")
            return 
    except Exception as e:
        conn.rollback()
        print(e)
        return None, f"Erreur lors de la création de l'utilisateur: {e}"
        
    finally:
        if cursor:
            cursor.close()
        conn.close()

    return

def create_url(url) :
    # """
    # CREATE TABLE urls (
    # url_id SERIAL PRIMARY KEY,
    # url TEXT NOT NULL,
    # domain VARCHAR(255) NOT NULL,
    # path TEXT,
    # query_params TEXT,
    # scheme VARCHAR(10) NOT NULL, -- http ou https
    # submit_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    # first_seen_date TIMESTAMP NOT NULL,
    # last_seen_date TIMESTAMP NOT NULL,
    # submitter_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    # is_malicious BOOLEAN DEFAULT NULL -- NULL si non déterminé, TRUE/FALSE sinon
    # );
    # """
    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    submit_date = datetime.datetime.now()
    last_seen_date = datetime.datetime.now()
    first_seen_date = datetime.datetime.now()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            # Insérer le nouvel utilisateur
            
            cursor.execute("SELECT setval('urls_url_id_seq', (SELECT MAX(url_id) FROM urls))")
            
            # Insérer le nouvel utilisateur en utilisant les paramètres passés à la fonction
            insert_script = '''
                INSERT INTO urls 
                (url, domain, path, scheme, submit_date, first_seen_date,last_seen_date,submitter_id) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) 
                RETURNING url_id
            
            '''
            insert_values = url,extract_domain(url),extract_path(url),get_scheme(url),submit_date,first_seen_date, last_seen_date, st.session_state.user['user_id']
            
            cursor.execute(insert_script, insert_values)
            
            #print(url,extract_domain(url),extract_path(url),get_scheme(url),submit_date,first_seen_date, last_seen_date, st.session_state.user['user_id'])
            
            # Récupérer l'ID attribué
            new_url_id = cursor.fetchone()[0]
            print("aan",new_url_id)
            conn.commit()
            
            
            return new_url_id, None
    except Exception as e:
        conn.rollback()
        print(e)
        return None, f"Erreur lors de la création de l'utilisateur: {e}"
        
    finally:
        if cursor:
            cursor.close()
        conn.close()

#####################################   IP   ############################################################################################
           
def show_verifier_ip():
    
    #input = st.text_input("text", key="ip_input")

    
        
    #st.button("clear text input", on_click=clear_text)
    
    
    
    st.title("Vérifier une adresse IP")
    ip = st.text_input("Entrez l'adresse IP à vérifier", key="ip_input")
    
    def ip_version():
        try:
            ip_obj = ipaddress.ip_address(ip)  # Vérifie si c'est une IP valide
            create_ip(ip,ip_obj.version)
            update_url_quota()
            return "IPv4" if ip_obj.version == 4 else "IPv6"
        except ValueError:
            st.session_state["ip_input"] = ""
            st.warning("⚠️ Veuillez entrer une adresse IPV4 ou IPV6")
            return False
            
            
    st.button(label="Vérifier", key="verify_ip_btn",on_click=ip_version)
        

def create_ip(ip,ip_v) :
    

#     ip_id SERIAL PRIMARY KEY,
#     ip_address VARCHAR(45) NOT NULL UNIQUE,  -- Format IPv4 ou IPv6 (IPv6 peut nécessiter jusqu'à 45 caractères)
#     ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),  -- IPv4 ou IPv6
#     first_seen_date TIMESTAMP NOT NULL,
#     last_seen_date TIMESTAMP NOT NULL,
#     submit_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
#     submitter_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
#     is_malicious BOOLEAN DEFAULT NULL -- NULL si non déterminé, TRUE si malveillante, FALSE si sûre

    conn = get_db_connection()
    if not conn:
        return None, "Erreur de connexion à la base de données"
    
    cursor = None
    submit_date = datetime.datetime.now()
    last_seen_date = datetime.datetime.now()
    first_seen_date = datetime.datetime.now()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            # Insérer le nouvel utilisateur
            
            cursor.execute("SELECT setval('ip_addresses_ip_id_seq', (SELECT MAX(ip_id) FROM ip_addresses))")
            
            # Insérer le nouvel utilisateur en utilisant les paramètres passés à la fonction
            insert_script = '''
                INSERT INTO ip_addresses 
                (ip_address, ip_version, first_seen_date, last_seen_date, submit_date, submitter_id) 
                VALUES (%s, %s, %s, %s, %s, %s) 
                RETURNING ip_id
                
            
            '''
            insert_values = ip,ip_v,first_seen_date,last_seen_date,submit_date, st.session_state.user['user_id']
            
            cursor.execute(insert_script, insert_values)
            
            
            # Récupérer l'ID attribué
            new_ip_id = cursor.fetchone()[0]
            print(new_ip_id)
            conn.commit()
            return new_ip_id, None
    except Exception as e:
        conn.rollback()
        print(e)
    
        return None, f"Erreur lors de la création de l'utilisateur: {e}"
        
    finally:
        if cursor:
            cursor.close()
        conn.close()

def show_analyses():
    st.title("Mes analyses")
    st.write("Historique de vos analyses:")
    files = None
    col1, col2 = st.columns(2)
    with col1:
        mine_button = st.button(label="mes analyses")
        if mine_button:
            files = retrieve_users_files(st.session_state.user['user_id'])
            # ips = retrieve_users_ips(st.session_state.user['user_id'])
            urls = retrieve_users_urls(st.session_state.user['user_id'])
    with col2:
        all_button = st.button(label="toutes les analyse")
        if all_button:
            files = retrieve_all_files()
            # ips = retrieve_all_ips()
            # urls = retrieve_all_urls()

    
    
    if not isinstance(files, list):
        st.write("Vous n'avez effectué aucune analyse pour le moment...")
        return
    
    if len(files) == 0:
        st.write("Vous n'avez effectué aucune analyse pour le moment...")
        return
    
    analyses = []
    for file in files:
        file_data = {
            "file name": file.get('file_name', ''),
            "file type": file.get('file_type', ''),
            "upload date": file.get('upload_date', '').strftime("%d/%m/%Y") if file.get('upload_date') else '',
            "scan status": file.get('scan_status', ''),
            "detection status": file.get('detection_status', '')
        }
        analyses.append(file_data)
    
    # Conversion de la liste de dictionnaires en DataFrame
    df_analyses = pd.DataFrame(analyses)
    
    selection = dataframe_with_selections(df_analyses)
    
    
    # st.session_state.selected_data = selection
    # print(" st.session_state.selected_data   ", st.session_state.selected_data)
    # st.write("Your selection:")
    # st.write(selection)


def dataframe_with_selections(df):
    # Créer un conteneur pour l'avertissement
    warning_container = st.empty()
    
    # Afficher l'avertissement initial
    warning_container.warning("Aucune ligne sélectionnée. Veuillez sélectionner une ligne pour afficher une analyse.")
    
    # Afficher le tableau sans colonne de sélection
    st.dataframe(df)
    
    # Créer une liste de sélection sous le tableau
    file_names = df["file name"].tolist()
    selected_file = st.selectbox("Sélectionnez un fichier pour voir son analyse :", [""] + file_names)
    
    if selected_file:
        warning_container.empty()  # Supprimer l'avertissement
        selected_row = df[df["file name"] == selected_file]
        st.write(selected_row.to_dict('dict'))
        return selected_row.to_dict('dict')
    else:
        return pd.DataFrame()  # Retourner un DataFrame vide si rien n'est sélectionné

def show_details(a):
    st.title("details")
    st.write(a)



def show_statistiques():
    st.title("Statistiques")
    import numpy as np
    import pandas as pd
    
    # Données de simulation
    dates = pd.date_range(start="2025-03-01", end="2025-03-19")
    analyses = np.random.randint(0, 10, size=len(dates))
    
    data = pd.DataFrame({
        "Date": dates,
        "Analyses": analyses
    })
    
    st.subheader("Analyses par jour")
    st.line_chart(data.set_index("Date"))
    
   
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("select COUNT(file_name) from files where submitter_id = %s",str(st.session_state.user['user_id']))
        nb_file = cursor.fetchone()
        cursor.execute("select count(url_id) from urls where submitter_id = %s",str(st.session_state.user['user_id']))
        nb_url = cursor.fetchone()
        cursor.execute("select count(ip_id) from ip_addresses where submitter_id = %s",str(st.session_state.user['user_id']))
        nb_ip = cursor.fetchone()
        st.subheader("Répartition par type")
        types = {
        "Fichiers": nb_file[0],
        "URLs": nb_url[0],
        "IPs": nb_ip[0]
        }
        st.bar_chart(types)
    except Exception as e:
        st.error(e)
        
    finally:
        if cursor:
            cursor.close()
        conn.close()

#def analyse recente ################################################################################################################################



# def show_login_page():
#     st.title("Connexion à VirusScan")
    
#     with st.form("login_form"):
#         email = st.text_input("Email", placeholder="Entrez votre adresse email")
#         password = st.text_input("Mot de passe", type="password", placeholder="Entrez votre mot de passe")
        
#         col1, col2, col3 = st.columns(3)
#         with col1:
#             login_button = st.form_submit_button(label="Se connecter")
#         with col2:
#             st.write("Pas encore de compte ?")
#         with col3:
#             signup_button = st.form_submit_button(label="Créer un compte")
        
#         if login_button:
#             if not email or not password:
#                 st.error("Veuillez entrer votre email et votre mot de passe !")
#             else:
#                 user, error = authenticate_user(email, password)
                
#                 if error:
#                     st.error(error)
#                 else:
#                     st.session_state.logged_in = True
#                     st.session_state.user = user
#                     st.session_state.current_page = "dashboard"
#                     st.success(f"Connexion réussie ! Bienvenue, {user['username']}.")
#                     st.rerun()
        
#         if signup_button:
#             st.session_state.page = 'signup'
#             st.rerun()

def show_signup_page():
    st.title("Création de compte VirusScan")
    
    with st.form("signup_form"):
        username = st.text_input("Nom d'utilisateur", placeholder="Entrez votre nom d'utilisateur")
        email = st.text_input("Email", placeholder="Entrez votre adresse email")
        password = st.text_input("Mot de passe", type="password", placeholder="Entrez votre mot de passe")
        password_confirm = st.text_input("Confirmer le mot de passe", type="password", placeholder="Confirmez votre mot de passe")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            submit_button = st.form_submit_button(label="Créer un compte")
        with col2:
            st.write("Vous avez déjà un compte ?")
        with col3:
            login_button = st.form_submit_button(label="Se connecter")
        
        if submit_button:
            # Validation des entrées
            if not email or '@' not in email:
                st.error("Veuillez entrer une adresse email valide !")
            elif not password:
                st.error("Veuillez entrer un mot de passe !")
            elif password != password_confirm:
                st.error("Les mots de passe ne correspondent pas !")
            elif not username:
                st.error("Veuillez entrer un nom d'utilisateur !")
            else:
                # Création du compte
                user_id, error = create_user(username, email, password)
                
                if error:
                    st.error(error)
                else:
                    st.success(f"Compte créé avec succès!")
                    st.info("Vous pouvez maintenant vous connecter avec vos identifiants.")
                    # Rediriger vers la page de connexion après 2 secondes
                    st.session_state.page = 'login'
                    st.rerun()
        
        if login_button:
            st.session_state.page = 'login'
            st.rerun()

# Application du style personnalisé
def set_sidebar_style():
    st.markdown("""
    <style>
    /* Style de la barre latérale */
    section[data-testid="stSidebar"] > div {
        background-color: #f0f2f6;
        padding: 0.5rem;
    }
    
    /* Style des boutons pour qu'ils ressemblent à des éléments de menu */
    .stButton > button {
        width: 100%;
        text-align: left;
        background-color: transparent;
        border: none;
        padding: 0.75rem 1rem;
        margin: 2px 0;
        border-radius: 4px;
        color: #262730;
    }
    
    /* Survol des boutons */
    .stButton > button:hover {
        background-color: rgba(151, 166, 195, 0.25);
    }
    
    /* Style pour le bouton sélectionné */
    .stButton > button.selected {
        background-color: #e0e5eb;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

def sidebar():
    with st.sidebar:
        st.title("VirusScan")
        st.markdown("---")
        
        # Buttons with unique keys to prevent duplicate element error
        if st.button(label="Tableau de bord", key="nav_dashboard", use_container_width=True):
            st.session_state.current_page = "dashboard"
            st.rerun()
            
        if st.button(label="Analyser un fichier 📄", key="nav_file", use_container_width=True):
            st.session_state.current_page = "analyser_fichier"
            st.rerun()

        if st.button(label="Scanner une URL 🌐", key="nav_url", use_container_width=True):
            st.session_state.current_page = "scanner_url"
            st.rerun()

        # if st.button(label="🔎 Vérifier un hash", key="nav_hash", use_container_width=True):
        #     st.session_state.current_page = "verifier_hash"
        #     st.rerun()

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

# Interface Streamlit

def apply_custom_style():
    """Applique un style personnalisé à l'application Streamlit."""
    st.markdown("""
    <style>
    /* Palette de couleurs beige/marron */
    :root {
        --primary-color: #c19a6b;      /* Marron moyen */
        --secondary-color: #e6d7c3;    /* Beige clair */
        --accent-color: #8b5a2b;       /* Marron foncé */
        --background-color: #f8f4e9;   /* Beige très clair */
        --text-color: #4e3629;         /* Marron très foncé */
        --hover-color: #d6c6b6;        /* Beige légèrement plus foncé */
        --success-color: #7d9e7d;      /* Vert doux */
        --warning-color: #d8b365;      /* Ambre */
        --error-color: #cd5c5c;        /* Rouge doux */
    }
    
    /* Style global */
    .stApp {
        background-color: var(--background-color);
        color: var(--text-color);
    }
    
    /* En-têtes */
    h1, h2, h3, h4, h5, h6 {
        color: var(--accent-color);
        font-family: 'Helvetica Neue', sans-serif;
        letter-spacing: 0.5px;
    }
    
    h1 {
        border-bottom: 2px solid var(--primary-color);
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    
    /* Boutons */
    .stButton > button {
        background-color: var(--primary-color);
        color: white;
        border-radius: 6px;
        border: none;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    .stButton > button:hover {
        background-color: var(--accent-color);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        transform: translateY(-2px);
    }
    
    .stButton > button:active {
        transform: translateY(1px);
        box-shadow: 0 1px 3px rgba(0,0,0,0.2);
    }
    
    /* Boîtes de texte */
    .stTextInput > div > div > input {
        border: 2px solid var(--secondary-color);
        border-radius: 6px;
        padding: 0.5rem;
        transition: border 0.3s ease;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(193, 154, 107, 0.2);
    }
    
    /* Cartes pour les statistiques */
    .stat-card {
        background-color: white;
        border-radius: 8px;
        padding: 1.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        border-left: 5px solid var(--primary-color);
    }
    
    .stat-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.1);
    }
    
    /* Alertes et messages */
    .stAlert {
        border-radius: 8px;
        border: none;
        padding: 1rem;
    }
    
    .stSuccess {
        background-color: var(--success-color);
        opacity: 0.85;
    }
    
    .stWarning {
        background-color: var(--warning-color);
        opacity: 0.85;
    }
    
    .stError {
        background-color: var(--error-color);
        opacity: 0.85;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] > div {
        background-color: var(--secondary-color);
        padding: 1rem 0.5rem;
    }
    
    section[data-testid="stSidebar"] .stButton > button {
        width: 100%;
        text-align: left;
        background-color: transparent;
        color: var(--text-color);
        border: none;
        padding: 0.75rem 1rem;
        margin: 2px 0;
        border-radius: 4px;
        transition: all 0.2s ease;
        box-shadow: none;
    }
    
    section[data-testid="stSidebar"] .stButton > button:hover {
        background-color: var(--hover-color);
        transform: none;
        box-shadow: none;
    }
    
    section[data-testid="stSidebar"] .stButton > button.selected,
    section[data-testid="stSidebar"] .stButton > button:active {
        background-color: var(--primary-color);
        color: white;
        font-weight: bold;
        transform: none;
    }
    
    /* Animations pour les cartes et éléments */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .animate-fadeIn {
        animation: fadeIn 0.5s ease forwards;
    }
    
    /* Tables */
    .stTable {
        border-collapse: separate;
        border-spacing: 0;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    
    .stTable thead tr {
        background-color: var(--primary-color);
        color: white;
    }
    
    .stTable tr:nth-child(even) {
        background-color: var(--secondary-color);
    }
    
    .stTable tr:hover {
        background-color: var(--hover-color);
    }
    
    /* Style pour les métriques */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: bold;
        color: var(--accent-color);
    }
    
    [data-testid="stMetricLabel"] {
        font-size: 1rem;
        color: var(--text-color);
    }
    
    /* Formulaires */
    .stForm {
        background-color: white;
        padding: 2rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    
    /* Effets de loading */
    .loading-spinner {
        border: 4px solid var(--secondary-color);
        border-top: 4px solid var(--primary-color);
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 20px auto;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    </style>
    """, unsafe_allow_html=True)


def show_dashboard():
    st.markdown('<h1 class="animate-fadeIn">Bienvenue sur VirusScan</h1>', unsafe_allow_html=True)
    
    # Informations utilisateur avec animation
    st.markdown(f'<div class="animate-fadeIn" style="animation-delay: 0.1s;">', unsafe_allow_html=True)
    if st.session_state.user['is_admin']:
        st.markdown(f'<h3>👋 Bonjour, {st.session_state.user["username"]} (Administrateur)</h3>', unsafe_allow_html=True)
    else:
        st.markdown(f'<h3>👋 Bonjour, {st.session_state.user["username"]}</h3>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Statistiques rapides dans des cartes
    st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.2s;">', unsafe_allow_html=True)
    st.subheader("Vue d'ensemble")
    st.markdown('</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="stat-card animate-fadeIn" style="animation-delay: 0.3s;">', unsafe_allow_html=True)
        st.metric("Analyses effectuées", st.session_state.user['quota_used'])
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col2:
        st.markdown('<div class="stat-card animate-fadeIn" style="animation-delay: 0.4s;">', unsafe_allow_html=True)
        st.metric("Menaces détectées", "0")
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col3:
        st.markdown('<div class="stat-card animate-fadeIn" style="animation-delay: 0.5s;">', unsafe_allow_html=True)
        quota_used = st.session_state.user['quota_used']
        quota_limit = st.session_state.user['quota_limit']
        quota_percent = (quota_used / quota_limit) * 100
        st.metric("Quota utilisé", f"{quota_percent:.1f}%")
        
        # Barre de progression personnalisée
        progress_html = f"""
        <div style="margin-top: 10px;">
            <div style="height: 10px; width: 100%; background-color: #e6d7c3; border-radius: 5px;">
                <div style="height: 10px; width: {quota_percent}%; background-color: #c19a6b; border-radius: 5px;"></div>
            </div>
            <p style="margin-top: 5px; text-align: right; font-size: 0.8em;">{quota_used} / {quota_limit}</p>
        </div>
        """
        st.markdown(progress_html, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Actions rapides
    st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.6s;">', unsafe_allow_html=True)
    st.subheader("Actions rapides")
    
    actions_col1, actions_col2, actions_col3 = st.columns(3)
    with actions_col1:
        if st.button(label="📄 Analyser un fichier", key="quick_file_btn"):
            st.session_state.current_page = "analyser_fichier"
            st.rerun()
            
    with actions_col2:
        if st.button(label="🌐 Scanner une URL", key="quick_url_btn"):
            st.session_state.current_page = "scanner_url"
            st.rerun()
            
    # with actions_col3:
    #     if st.button(label="🔍 Vérifier un hash", key="quick_hash_btn"):
    #         st.session_state.current_page = "verifier_hash"
    #         st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Analyses récentes
    st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.7s; margin-top: 30px;">', unsafe_allow_html=True)
    st.subheader("Analyses récentes")
    
    # Exemple de données d'analyse récentes
    recent_analyses = [
        {"date": "19/03/2025", "type": "Fichier", "nom": "document.pdf", "résultat": "Sécurisé"},
        {"date": "18/03/2025", "type": "URL", "nom": "exemple.com", "résultat": "Sécurisé"},
        {"date": "17/03/2025", "type": "IP", "nom": "192.168.1.1", "résultat": "Sécurisé"}
    ]
    
    # Créer un tableau personnalisé
    table_html = """
    <table style="width:100%; border-collapse: separate; border-spacing: 0; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-top: 10px;">
        <thead>
            <tr style="background-color: #c19a6b; color: white;">
                <th style="padding: 12px 15px; text-align: left;">Date</th>
                <th style="padding: 12px 15px; text-align: left;">Type</th>
                <th style="padding: 12px 15px; text-align: left;">Nom</th>
                <th style="padding: 12px 15px; text-align: left;">Résultat</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for i, analysis in enumerate(recent_analyses):
        bg_color = "#f8f4e9" if i % 2 == 0 else "#e6d7c3"
        result_color = "#7d9e7d" if analysis["résultat"] == "Sécurisé" else "#cd5c5c"
        
        table_html += f"""
        <tr style="background-color: {bg_color}; transition: background-color 0.3s ease;">
            <td style="padding: 12px 15px;">{analysis["date"]}</td>
            <td style="padding: 12px 15px;">{analysis["type"]}</td>
            <td style="padding: 12px 15px;">{analysis["nom"]}</td>
            <td style="padding: 12px 15px;">
                <span style="background-color: {result_color}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.85em;">
                    {analysis["résultat"]}
                </span>
            </td>
        </tr>
        """
    
    table_html += """
        </tbody>
    </table>
    """
    
    st.markdown(table_html, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)



def show_analyser_fichier():
    st.markdown('<h1 class="animate-fadeIn">Analyser un fichier</h1>', unsafe_allow_html=True)
    
    # Conteneur principal avec animation
    with st.container():
        st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.1s;">', unsafe_allow_html=True)
        
        # Instructions
        st.markdown("""
        <div style="background-color: #e6d7c3; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h4 style="margin-top: 0;">📋 Instructions</h4>
            <p>Sélectionnez un fichier à analyser. Notre système vérifiera la présence de menaces et calculera les hash cryptographiques.</p>
            <p><strong>Types de fichiers supportés:</strong> EXE, DLL, PDF, DOC, DOCX, XLS, XLSX, JS, HTML, ZIP</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Zone de dépôt de fichier stylisée
        upload_html = """
        <div style="border: 2px dashed #c19a6b; border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px;">
            <p>Glissez-déposez votre fichier ici ou cliquez pour parcourir</p>
        </div>
        """
        st.markdown(upload_html, unsafe_allow_html=True)
        
        # Widget de téléchargement de fichier
        uploaded_file = st.file_uploader(label="Sélectionner un fichier", type=["exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "js", "html", "zip"])
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        if uploaded_file is not None:
            st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.2s;">', unsafe_allow_html=True)
            
            # Informations sur le fichier
            file_info_html = f"""
            <div style="background-color: white; padding: 15px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <h4 style="margin-top: 0; color: #8b5a2b;">📄 Fichier reçu</h4>
                <p><strong>Nom:</strong> {uploaded_file.name}</p>
                <p><strong>Type:</strong> {uploaded_file.type if hasattr(uploaded_file, 'type') else 'Non détecté'}</p>
                <p><strong>Taille:</strong> {uploaded_file.size} octets</p>
            </div>
            """
            st.markdown(file_info_html, unsafe_allow_html=True)
            
            # Créer un fichier temporaire pour l'analyse
            with st.spinner("Préparation du fichier..."):
                temp_file_path = os.path.join(os.getcwd(), "temp_upload", uploaded_file.name)
                os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
                
                with open(temp_file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                # Bouton d'analyse
                analysis_clicked = st.button(label="🔍 Lancer l'analyse approfondie", key="launch_analysis_btn")
                
                if analysis_clicked:
                    update_url_quota()
                    # Afficher un spinner personnalisé
                    st.markdown('<div class="loading-spinner"></div>', unsafe_allow_html=True)
                    st.markdown('<p style="text-align: center; margin-bottom: 20px;">Analyse en cours...</p>', unsafe_allow_html=True)
                    
                    try:
                        # Analyse du fichier
                        analysis_result = analyze_file(temp_file_path)
                        # Stocker les résultats dans session_state
                        st.session_state.analysis_result = analysis_result
                        st.session_state.analysis_complete = True
                        st.session_state.uploaded_file_name = uploaded_file.name
                        st.session_state.uploaded_file_path = temp_file_path
                        
                        # Affichage immédiat des résultats
                        st.success("✅ Analyse terminée avec succès!")
                    
                    except Exception as e:
                        st.error(f"❌ Erreur lors de l'analyse: {str(e)}")
                        st.session_state.analysis_complete = False
                    
                # Afficher les résultats si disponibles (que ce soit de l'analyse qu'on vient de faire ou d'une précédente)
                if 'analysis_complete' in st.session_state and st.session_state.analysis_complete:
                    analysis_result = st.session_state.analysis_result
                    
                    # Tableau de résultats avec style amélioré
                    st.markdown('<h4 style="margin-top: 20px;">Résultats d\'analyse</h4>', unsafe_allow_html=True)
                    
                    # Affichage des informations de base
                    info_cols = st.columns(2)
                    
                    with info_cols[0]:
                        st.markdown("**Informations générales**")
                        st.markdown(f"**Type MIME:** {analysis_result['mime_type']}")
                        st.markdown(f"**Extension:** {analysis_result['file_extension']}")
                        st.markdown(f"**Taille:** {analysis_result['size_bigint']} octets")
                    
                    # Affichage des hash avec style
                    with info_cols[1]:
                        st.markdown("**Empreintes cryptographiques (hash)**")
                        
                        # Style pour les hash
                        hash_style = """
                        <style>
                        .hash-box {
                            background-color: #f0f0f0;
                            padding: 5px 10px;
                            border-radius: 4px;
                            font-family: monospace;
                            overflow-x: auto;
                            margin: 5px 0;
                        }
                        </style>
                        """
                        st.markdown(hash_style, unsafe_allow_html=True)
                        
                        # Affichage des hash dans des boîtes stylisées
                        st.markdown(f"**MD5:**")
                        st.markdown(f"<div class='hash-box'>{analysis_result['hashes']['md5']}</div>", unsafe_allow_html=True)
                        
                        st.markdown(f"**SHA-1:**")
                        st.markdown(f"<div class='hash-box'>{analysis_result['hashes']['sha1']}</div>", unsafe_allow_html=True)
                        
                        st.markdown(f"**SHA-256:**")
                        st.markdown(f"<div class='hash-box'>{analysis_result['hashes']['sha256']}</div>", unsafe_allow_html=True)
                    
                    # Bouton d'enregistrement séparé du flux d'analyse
                    save_clicked = st.button(label="💾 Enregistrer l'analyse", key="saveanalysisbtn")
                    
                    if save_clicked:
                        # Ajouter le fichier à la base de données
                        file_id = insert_file(
                            hash_md5=analysis_result['hashes']['md5'],
                            hash_sha1=analysis_result['hashes']['sha1'],
                            hash_sha256=analysis_result['hashes']['sha256'],
                            file_name=st.session_state.uploaded_file_name,
                            file_size=analysis_result['size_bigint'],
                            file_type=analysis_result['mime_type'],
                            submitter_id=st.session_state.user['user_id']
                        )
                        
                        if file_id:
                            st.success(f"✅ Analyse enregistrée avec succès (ID: {file_id})")
                        else:
                            st.error("❌ Erreur lors de l'enregistrement de l'analyse")
                
                # Nettoyage du fichier temporaire si demandé
                if st.button(label="🗑️ Nettoyer", key="clean_temp_btn"):
                    try:
                        if 'uploaded_file_path' in st.session_state:
                            os.remove(st.session_state.uploaded_file_path)
                            st.session_state.pop('analysis_complete', None)
                            st.session_state.pop('analysis_result', None)
                            st.session_state.pop('uploaded_file_name', None)
                            st.session_state.pop('uploaded_file_path', None)
                            st.success("✅ Fichier temporaire nettoyé")
                            st.rerun()
                    except Exception as e:
                        st.error(f"❌ Erreur lors du nettoyage: {str(e)}")
            
            with col2:
                # Informations complémentaires
                st.markdown("""
                <div style="background-color: #f8f4e9; padding: 15px; border-radius: 8px; margin-top: 20px;">
                    <h4 style="margin-top: 0; color: #8b5a2b;">ℹ️ À propos de l'analyse</h4>
                    <p>Notre analyse calcule les empreintes cryptographiques (hash) suivantes:</p>
                    <ul>
                        <li><strong>MD5:</strong> Rapide mais moins sécurisé</li>
                        <li><strong>SHA-1:</strong> Standard de sécurité intermédiaire</li>
                        <li><strong>SHA-256:</strong> Haute sécurité, recommandé</li>
                    </ul>
                    <p>Ces hash permettent d'identifier de manière unique le fichier et de vérifier s'il a déjà été signalé comme malveillant.</p>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="animate-fadeIn" style="animation-delay: 0.2s; text-align: center; color: #8b5a2b; margin: 30px 0;">', unsafe_allow_html=True)
            st.warning("⚠️ Veuillez choisir un fichier à analyser")
            st.markdown('</div>', unsafe_allow_html=True)




# Modifiez la fonction show_login_page pour une meilleure présentation
def show_login_page():
    st.markdown("""
    <style>
    .login-container {
        max-width: 500px;
        margin: 0 auto;
        padding: 30px;
        background-color: white;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .login-header {
        text-align: center;
        margin-bottom: 20px;
    }
    
    .login-logo {
        font-size: 2.5em;
        color: #8b5a2b;
        margin-bottom: 10px;
    }
    
    .login-title {
        color: #8b5a2b;
        margin-bottom: 20px;
    }
    
    .form-divider {
        height: 1px;
        background-color: #e6d7c3;
        margin: 20px 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="login-container animate-fadeIn">
        <div class="login-header">
            <div class="login-logo">🔒</div>
            <h1 class="login-title">VirusScan</h1>
        </div>
        <p style="text-align: center; margin-bottom: 30px;">Votre solution professionnelle d'analyse de sécurité</p>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        email = st.text_input("Email", placeholder="Entrez votre adresse email")
        password = st.text_input("Mot de passe", type="password", placeholder="Entrez votre mot de passe")
        
        st.markdown('<div class="form-divider"></div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            login_button = st.form_submit_button(label="Se connecter")
        with col2:
            signup_button = st.form_submit_button(label="Créer un compte")
        
        if login_button:
            if not email or not password:
                st.error("⚠️ Veuillez entrer votre email et votre mot de passe!")
            else:
                with st.spinner("Connexion en cours..."):
                    user, error = authenticate_user(email, password)
                    
                    if error:
                        st.error(f"❌ {error}")
                    else:
                        st.session_state.logged_in = True
                        st.session_state.user = user
                        st.session_state.current_page = "dashboard"
                        st.success(f"✅ Connexion réussie! Bienvenue, {user['username']}.")
                        st.rerun()
        
        if signup_button:
            st.session_state.page = 'signup'
            st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)
    
def main():
    # Initialiser les états de session
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "dashboard"
    if 'details' not in st.session_state:
        st.session_state.details = False
    if 'selected_data' not in st.session_state:
        st.session_state.selected_data = None

    # Appliquer le style personnalisé
    apply_custom_style()
    
    # Titre de la page (onglet navigateur)
    # st.set_page_config(
    #     page_title="VirusScan - Analyse de Sécurité",
    #     page_icon="🔒",
    #     layout="wide"
    # )
    
    # Afficher la page appropriée
    if st.session_state.logged_in:
        sidebar()
        
        if st.session_state.current_page == "dashboard":
            show_dashboard()
        elif st.session_state.current_page == "analyser_fichier":
            show_analyser_fichier()
        elif st.session_state.current_page == "scanner_url":
            show_scanner_url()
        elif st.session_state.current_page == "verifier_ip":
            show_verifier_ip()
        elif st.session_state.current_page == "analyses":
            show_analyses()
        elif st.session_state.current_page == "statistiques":
            show_statistiques()
        # elif st.session_state.current_page == "verifier_hash":
        #     show_verifier_hash()
        elif st.session_state.current_page == "details":
            show_details(st.session_state.selected_data)
            
            # Ajouter un bouton de retour
            if st.button("Retour"):
                st.session_state.current_page = 'analyses'
                st.rerun()
    elif st.session_state.page == 'login':
        show_login_page()
    else:
        show_signup_page()

if __name__ == "__main__":
    main()







































