import logging
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
import os

from middleware.error_handler import ValidationError
from models.user import User
from services.sandbox_service import SandboxService

logger = logging.getLogger(__name__)
sandbox_service = SandboxService()

def run_file():
    """Exécute un fichier dans l'environnement sandbox"""
    try:
        # Vérifier si un fichier a été uploadé
        if 'file' not in request.files:
            raise ValidationError("Aucun fichier n'a été fourni")
        
        file = request.files['file']
        if file.filename == '':
            raise ValidationError("Aucun fichier sélectionné")
        
        # Vérifier si l'extension est autorisée pour le sandbox
        allowed_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            raise ValidationError(f"Extension de fichier non autorisée pour le sandbox. Extensions acceptées: {', '.join(allowed_extensions)}")
        
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Exécuter le fichier dans le sandbox
        results = sandbox_service.run_file(file, user_id)
        
        # Mettre à jour le quota de l'utilisateur (2 unités pour une analyse sandbox)
        user = User.get_by_id(user_id)
        if user:
            user.update_quota(2)
        
        return jsonify({
            'success': True,
            'message': 'Analyse sandbox réussie',
            'results': results
        }), 200
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse sandbox: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de l'analyse sandbox: {str(e)}"
        }), 500

def get_run_results(run_id):
    """Récupère les résultats d'une analyse sandbox"""
    try:
        # Récupérer les résultats
        results = sandbox_service.get_run_results(run_id)
        
        return jsonify({
            'success': True,
            'run_id': run_id,
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de la récupération des résultats: {str(e)}"
        }), 500

def get_sandbox_history():
    """Récupère l'historique des analyses sandbox"""
    try:
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Récupérer le nombre de résultats demandés
        limit = request.args.get('limit', 10, type=int)
        
        # Récupérer l'historique
        history = sandbox_service.get_sandbox_history(user_id, limit)
        
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