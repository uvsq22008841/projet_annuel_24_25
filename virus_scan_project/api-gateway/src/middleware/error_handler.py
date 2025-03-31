from flask import jsonify
import logging

logger = logging.getLogger(__name__)

class APIError(Exception):
    """Classe de base pour les erreurs d'API personnalisées"""
    def __init__(self, message, status_code=400, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or {})
        rv['success'] = False
        rv['message'] = self.message
        return rv

class ResourceNotFoundError(APIError):
    """Erreur quand une ressource n'est pas trouvée"""
    def __init__(self, message="Ressource non trouvée", payload=None):
        super().__init__(message, status_code=404, payload=payload)

class AuthenticationError(APIError):
    """Erreur d'authentification"""
    def __init__(self, message="Authentification requise", payload=None):
        super().__init__(message, status_code=401, payload=payload)

class AuthorizationError(APIError):
    """Erreur d'autorisation"""
    def __init__(self, message="Accès non autorisé", payload=None):
        super().__init__(message, status_code=403, payload=payload)

class ValidationError(APIError):
    """Erreur de validation des données"""
    def __init__(self, message="Données invalides", payload=None):
        super().__init__(message, status_code=400, payload=payload)

class ServiceError(APIError):
    """Erreur de service interne"""
    def __init__(self, message="Erreur de service interne", payload=None):
        super().__init__(message, status_code=500, payload=payload)

def register_error_handlers(app):
    """Enregistre les gestionnaires d'erreurs pour l'application Flask"""
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response
    
    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({
            'success': False,
            'message': 'Route non trouvée'
        }), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({
            'success': False,
            'message': 'Méthode non autorisée'
        }), 405
    
    @app.errorhandler(500)
    def handle_server_error(error):
        logger.error(f"Erreur serveur: {str(error)}")
        return jsonify({
            'success': False,
            'message': 'Erreur serveur interne'
        }), 500