import requests
import logging
from config.config import Config

logger = logging.getLogger(__name__)

class URLService:
    """Service pour l'analyse d'URLs"""
    
    def __init__(self):
        config = Config.get_config()
        self.api_url = config.URL_ANALYSIS_URL
        self.timeout = config.URL_ANALYSIS_TIMEOUT
    
    def analyze_url(self, url, user_id):
        """
        Analyse une URL
        
        Args:
            url: URL à analyser
            user_id: ID de l'utilisateur qui soumet l'URL
            
        Returns:
            Résultats de l'analyse
        """
        try:
            # Préparer les données pour l'analyse
            data = {
                'url': url,
                'user_id': user_id
            }
            
            # Envoyer l'URL pour analyse
            response = requests.post(
                f"{self.api_url}/analyze",
                json=data,
                timeout=self.timeout
            )
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de l'analyse de l'URL: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de l'analyse de l'URL: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'URL: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de l'analyse de l'URL: {str(e)}"
            }
    
    def get_url_history(self, user_id, limit=10):
        """
        Récupère l'historique des analyses d'URLs d'un utilisateur
        
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