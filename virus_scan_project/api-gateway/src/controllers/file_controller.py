import logging
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from werkzeug.utils import secure_filename
import os

from middleware.error_handler import ValidationError
from models.user import User
from services.file_service import FileService

logger = logging.getLogger(__name__)
file_service = FileService()

def analyze_file():
    """Analyse un fichier"""
    try:
        # Vérifier si un fichier a été uploadé
        if 'file' not in request.files:
            raise ValidationError("Aucun fichier n'a été fourni")
        
        file = request.files['file']
        if file.filename == '':
            raise ValidationError("Aucun fichier sélectionné")
        
        # Vérifier si l'extension est autorisée
        allowed_extensions = os.environ.get('ALLOWED_FILE_TYPES', 
                                           '.exe,.dll,.pdf,.doc,.docx,.xls,.xlsx,.js,.vbs,.bat,.ps1,.jar').split(',')
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            raise ValidationError(f"Extension de fichier non autorisée. Extensions acceptées: {', '.join(allowed_extensions)}")
        
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Vérifier si l'analyse comportementale est demandée
        sandbox_enabled = request.form.get('sandbox_enabled', 'false').lower() == 'true'
        
        # Analyser le fichier
        results = file_service.analyze_file(file, user_id, sandbox_enabled)
        
        # Mettre à jour le quota de l'utilisateur
        user = User.get_by_id(user_id)
        if user:
            user.update_quota(1)
        
        return jsonify({
            'success': True,
            'message': 'Analyse du fichier réussie',
            'results': results
        }), 200
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de l'analyse du fichier: {str(e)}"
        }), 500

def lookup_hash():
    """Vérifie si un hash est présent dans la base de signatures"""
    try:
        data = request.get_json()
        
        # Valider les données
        if not data:
            raise ValidationError("Données manquantes")
        
        if 'hash' not in data or not data['hash']:
            raise ValidationError("Hash manquant")
        
        hash_type = data.get('type', 'md5')
        if hash_type not in ['md5', 'sha1', 'sha256']:
            raise ValidationError("Type de hash non valide. Valeurs acceptées: md5, sha1, sha256")
        
        # Effectuer la recherche
        results = file_service.lookup_hash(data['hash'], hash_type)
        
        return jsonify({
            'success': True,
            'hash': data['hash'],
            'type': hash_type,
            'results': results
        }), 200
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de la recherche du hash: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Erreur lors de la recherche du hash: {str(e)}"
        }), 500

def get_file_history():
    """Récupère l'historique des analyses de fichiers"""
    try:
        # Récupérer l'ID de l'utilisateur
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        
        # Récupérer le nombre de résultats demandés
        limit = request.args.get('limit', 10, type=int)
        
        # Récupérer l'historique
        history = file_service.get_analysis_history(user_id, limit)
        
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