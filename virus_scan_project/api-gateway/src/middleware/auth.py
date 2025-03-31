from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
import logging

logger = logging.getLogger(__name__)

def jwt_required(fn):
    """Middleware pour vérifier le JWT et authentifier l'utilisateur"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return fn(*args, **kwargs)
        except Exception as e:
            logger.error(f"Erreur d'authentification: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Token invalide ou expiré'
            }), 401
    return wrapper

def admin_required(fn):
    """Middleware pour vérifier les droits d'administrateur"""
    @wraps(fn)
    @jwt_required
    def wrapper(*args, **kwargs):
        try:
            current_user = get_jwt_identity()
            if current_user.get('role') != 'admin':
                return jsonify({
                    'success': False,
                    'message': 'Accès non autorisé. Droits administrateur requis.'
                }), 403
            return fn(*args, **kwargs)
        except Exception as e:
            logger.error(f"Erreur de vérification des droits admin: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la vérification des droits'
            }), 500
    return wrapper

def check_quota(fn):
    """Middleware pour vérifier le quota d'utilisateur"""
    @wraps(fn)
    @jwt_required
    def wrapper(*args, **kwargs):
        try:
            current_user = get_jwt_identity()
            if current_user.get('quota_used', 0) >= current_user.get('quota_limit', 100):
                return jsonify({
                    'success': False,
                    'message': 'Quota d\'analyse dépassé. Veuillez mettre à jour votre abonnement.',
                    'quota': {
                        'used': current_user.get('quota_used', 0),
                        'limit': current_user.get('quota_limit', 100)
                    }
                }), 429
            return fn(*args, **kwargs)
        except Exception as e:
            logger.error(f"Erreur de vérification du quota: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la vérification du quota'
            }), 500
    return wrapper