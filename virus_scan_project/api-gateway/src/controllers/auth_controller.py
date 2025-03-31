import logging
from flask import jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity

from middleware.error_handler import ValidationError, AuthenticationError
from models.user import User

logger = logging.getLogger(__name__)

def register():
    """Enregistre un nouvel utilisateur"""
    try:
        data = request.get_json()
        
        # Valider les données
        if not data:
            raise ValidationError("Données manquantes")
        
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                raise ValidationError(f"Le champ '{field}' est requis")
        
        # Vérifier si l'utilisateur existe déjà
        if User.get_by_username(data['username']):
            raise ValidationError("Ce nom d'utilisateur est déjà utilisé")
        
        if User.get_by_email(data['email']):
            raise ValidationError("Cette adresse email est déjà utilisée")
        
        # Créer un nouvel utilisateur
        user = User(
            username=data['username'],
            email=data['email'],
            password=User.hash_password(data['password']),
            role='user',
            quota_used=0,
            quota_limit=100
        )
        
        # Sauvegarder l'utilisateur
        user_id = user.save()
        if not user_id:
            raise ValidationError("Erreur lors de l'enregistrement de l'utilisateur")
        
        # Créer un token JWT
        access_token = create_access_token(identity=user.to_dict())
        
        return jsonify({
            'success': True,
            'message': 'Inscription réussie',
            'token': access_token,
            'user': user.to_dict()
        }), 201
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {str(e)}")
        raise ValidationError(str(e))

def login():
    """Authentifie un utilisateur"""
    try:
        data = request.get_json()
        
        # Valider les données
        if not data:
            raise ValidationError("Données manquantes")
        
        if 'username' not in data or not data['username']:
            raise ValidationError("Le nom d'utilisateur est requis")
        
        if 'password' not in data or not data['password']:
            raise ValidationError("Le mot de passe est requis")
        
        # Récupérer l'utilisateur
        user = User.get_by_username(data['username'])
        if not user:
            raise AuthenticationError("Nom d'utilisateur ou mot de passe incorrect")
        
        # Vérifier le mot de passe
        if not user.check_password(data['password']):
            raise AuthenticationError("Nom d'utilisateur ou mot de passe incorrect")
        
        # Créer un token JWT
        access_token = create_access_token(identity=user.to_dict())
        
        return jsonify({
            'success': True,
            'message': 'Connexion réussie',
            'token': access_token,
            'user': user.to_dict()
        }), 200
        
    except ValidationError as e:
        raise e
    except AuthenticationError as e:
        raise e
    except Exception as e:
        logger.error(f"Erreur lors de la connexion: {str(e)}")
        raise AuthenticationError(str(e))

def get_current_user():
    """Récupère les informations de l'utilisateur actuel"""
    try:
        current_user = get_jwt_identity()
        if not current_user:
            raise AuthenticationError("Utilisateur non authentifié")
        
        # Récupérer les données à jour de l'utilisateur
        user = User.get_by_id(current_user['user_id'])
        if not user:
            raise AuthenticationError("Utilisateur non trouvé")
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
        raise AuthenticationError(str(e))