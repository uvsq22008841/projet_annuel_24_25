import logging
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
import re

from middleware.error_handler import ValidationError
from models.user import User
from services.url_service import URLService

logger = logging.getLogger(__name__)
url_service = URLService()

def analyze_url():
    """Analyse une URL"""
    try:
        data = request.get_json()
        
        # Valider les données
        if not data:
            raise ValidationError("Données manquantes")
        
        if 'url' not in data or not data['url']:
            raise ValidationError("URL manquante")
        
        # Valider le format de l'URL
        url_pattern = re.compile(
            r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.-]*)*\/?$'
        )
        
        if not url_pattern.match(data['url']):
            raise ValidationError("Format d'URL invalide")
        
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Analyser l'URL
        results = url_service.analyze_url(data['url'], user_id)
        
        # Mettre à jour le quota de l'utilisateur
        user = User.get_by_id(user_id)
        if user:
            user.update_quota(1)
        
        return jsonify({
            'success': True,
            'message': 'Analyse de l\'URL réussie',
            'results': results
        }), 200
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'URL: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de l'analyse de l'URL: {str(e)}"
        }), 500

def get_url_history():
    """Récupère l'historique des analyses d'URLs"""
    try:
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Récupérer le nombre de résultats demandés
        limit = request.args.get('limit', 10, type=int)
        
        # Récupérer l'historique
        history = url_service.get_url_history(user_id, limit)
        
        return jsonify({
            'success': True,
            'history': history
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de la récupération de l'historique: {str(e)}"
        }), 500