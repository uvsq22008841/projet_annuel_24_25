import requests
import logging
from config.config import Config

logger = logging.getLogger(__name__)

class IPService:
    """Service pour l'analyse d'adresses IP"""
    
    def __init__(self):
        config = Config.get_config()
        self.api_url = config.IP_ANALYSIS_URL
        self.timeout = config.IP_ANALYSIS_TIMEOUT
    
    def analyze_ip(self, ip_address, user_id):
        """
        Analyse une adresse IP
        
        Args:
            ip_address: Adresse IP à analyser
            user_id: ID de l'utilisateur qui soumet l'IP
            
        Returns:
            Résultats de l'analyse
        """
        try:
            # Préparer les données pour l'analyse
            data = {
                'ip_address': ip_address,
                'user_id': user_id
            }
            
            # Envoyer l'IP pour analyse
            response = requests.post(
                f"{self.api_url}/analyze",
                json=data,
                timeout=self.timeout
            )
            
            # Vérifier la réponse
            if response.status_code != 200:
                logger.error(f"Erreur lors de l'analyse de l'IP: {response.text}")
                return {
                    'success': False,
                    'message': f"Erreur lors de l'analyse de l'IP: {response.status_code}"
                }
            
            # Retourner les résultats
            return response.json()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'IP: {str(e)}")
            return {
                'success': False,
                'message': f"Erreur lors de l'analyse de l'IP: {str(e)}"
            }
    
    def get_ip_history(self, user_id, limit=10):
        """
        Récupère l'historique des analyses d'IPs d'un utilisateur
        
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