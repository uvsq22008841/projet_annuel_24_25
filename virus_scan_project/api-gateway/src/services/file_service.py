import os
import requests
import logging
import tempfile
from werkzeug.utils import secure_filename
from config.config import Config

logger = logging.getLogger(__name__)

class FileService:
    """Service pour l'analyse de fichiers"""
    
    def __init__(self):
        config = Config.get_config()
        self.api_url = config.FILE_ANALYSIS_URL
        self.timeout = config.FILE_ANALYSIS_TIMEOUT
        self.upload_folder = config.UPLOAD_FOLDER
        
        # Créer le répertoire d'upload s'il n'existe pas
        if not os.path.exists(self.upload_folder):
            os.makedirs(self.upload_folder)
    
    def analyze_file(self, file, user_id, sandbox_enabled=False):
        """
        Analyse un fichier
        
        Args:
            file: Fichier à analyser (FileStorage)
            user_id: ID de l'utilisateur qui soumet le fichier
            sandbox_enabled: Active l'analyse comportementale
            
        Returns:
            Résultats de l'analyse
        """
        try:
            # Sauvegarder le fichier
            filename = secure_filename(file.filename)
            filepath = os.path.join(tempfile.gettempdir(), filename)
            file.save(filepath)
            
            # Préparer les données pour l'analyse
            files = {'file': (filename, open(filepath, 'rb'))}
            data = {
                'user_id': user_id,
                'sandbox_enabled': sandbox_enabled
            }
            
            # Envoyer le fichier pour analyse
            response = requests.post(
                f"{self.api_url}/analyze",
                files=files,
                data=data,
                timeout=self.timeout
            )
            
            # Nettoyer
            os.remove(filepath)
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de l'analyse du fichier: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de l'analyse du fichier: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de l'analyse du fichier: {str(e)}"
            }
    
    def lookup_hash(self, hash_value, hash_type="md5"):
        """
        Vérifie si un hash est présent dans la base de signatures
        
        Args:
            hash_value: Valeur du hash à vérifier
            hash_type: Type de hash (md5, sha1, sha256)
            
        Returns:
            Résultat de la recherche
        """
        try:
            # Envoyer la requête
            response = requests.get(
                f"{self.api_url}/lookup/{hash_type}/{hash_value}",
                timeout=self.timeout
            )
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de la recherche du hash: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de la recherche du hash: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de la recherche du hash: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de la recherche du hash: {str(e)}"
            }
    
    def get_analysis_history(self, user_id, limit=10):
        """
        Récupère l'historique des analyses de fichiers d'un utilisateur
        
        Args:
            user_id: ID de l'utilisateur
            limit: Nombre maximum de résultats
            
        Returns:
            Historique des analyses
        """
        try:
            # Envoyer la requête
            response = requests.get(
                f"{self.api_url}/history/{user_id}",
                params={'limit': limit},
                timeout=self.timeout
            )
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de la récupération de l'historique: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de la récupération de l'historique: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de la récupération de l'historique: {str(e)}"
            }