from flask import Blueprint
from controllers.auth_controller import register, login, get_current_user
from middleware.auth import jwt_required

auth_bp = Blueprint('auth', __name__)

# Route d'inscription
auth_bp.route('/register', methods=['POST'])(register)

# Route de connexion
auth_bp.route('/login', methods=['POST'])(login)

# Route pour récupérer l'utilisateur actuel
auth_bp.route('/me', methods=['GET'])(jwt_required(get_current_user))