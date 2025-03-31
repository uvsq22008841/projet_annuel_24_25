import requests
import logging
import os
import tempfile
from werkzeug.utils import secure_filename
from config.config import Config

logger = logging.getLogger(__name__)

class SandboxService:
    """Service pour l'analyse comportementale (sandbox)"""
    
    def __init__(self):
        config = Config.get_config()
        self.api_url = config.SANDBOX_URL
        self.timeout = config.SANDBOX_TIMEOUT
    
    def run_file(self, file, user_id):
        """
        Exécute un fichier dans l'environnement sandbox
        
        Args:
            file: Fichier à analyser (FileStorage)
            user_id: ID de l'utilisateur qui soumet le fichier
            
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
                'user_id': user_id
            }
            
            # Envoyer le fichier pour analyse sandbox
            response = requests.post(
                f"{self.api_url}/run",
                files=files,
                data=data,
                timeout=self.timeout
            )
            
            # Nettoyer
            os.remove(filepath)
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de l'analyse sandbox: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de l'analyse sandbox: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse sandbox: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de l'analyse sandbox: {str(e)}"
            }
    
    def get_run_results(self, run_id):
        """
        Récupère les résultats d'une analyse sandbox
        
        Args:
            run_id: ID de l'exécution sandbox
            
        Returns:
            Résultats de l'analyse
        """
        try:
            # Envoyer la requête
            response = requests.get(
                f"{self.api_url}/results/{run_id}",
                timeout=self.timeout
            )
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de la récupération des résultats: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de la récupération des résultats: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des résultats: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de la récupération des résultats: {str(e)}"
            }
    
    def get_sandbox_history(self, user_id, limit=10):
        """
        Récupère l'historique des analyses sandbox d'un utilisateur
        
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