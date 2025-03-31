import logging
import re
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity

from middleware.error_handler import ValidationError
from models.user import User
from services.ip_service import IPService

logger = logging.getLogger(__name__)
ip_service = IPService()

def analyze_ip():
    """Analyse une adresse IP"""
    try:
        data = request.get_json()
        
        # Valider les données
        if not data:
            raise ValidationError("Données manquantes")
        
        if 'ip_address' not in data or not data['ip_address']:
            raise ValidationError("Adresse IP manquante")
        
        # Valider le format de l'adresse IP (IPv4 ou IPv6)
        ip_pattern = re.compile(
            r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|'
            r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
        )
        
        if not ip_pattern.match(data['ip_address']):
            raise ValidationError("Format d'adresse IP invalide")
        
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Analyser l'adresse IP
        results = ip_service.analyze_ip(data['ip_address'], user_id)
        
        # Mettre à jour le quota de l'utilisateur
        user = User.get_by_id(user_id)
        if user:
            user.update_quota(1)
        
        return jsonify({
            'success': True,
            'message': 'Analyse de l\'adresse IP réussie',
            'results': results
        }), 200
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'adresse IP: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de l'analyse de l'adresse IP: {str(e)}"
        }), 500

def get_ip_history():
    """Récupère l'historique des analyses d'adresses IP"""
    try:
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Récupérer le nombre de résultats demandés
        limit = request.args.get('limit', 10, type=int)
        
        # Récupérer l'historique
        history = ip_service.get_ip_history(user_id, limit)
        
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