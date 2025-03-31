from flask import Blueprint
from controllers.url_controller import analyze_url, get_url_history
from middleware.auth import jwt_required, check_quota

url_bp = Blueprint('urls', __name__)

# Route pour analyser une URL
url_bp.route('/analyze', methods=['POST'])(jwt_required(check_quota(analyze_url)))

# Route pour récupérer l'historique des analyses
url_bp.route('/history', methods=['GET'])(jwt_required(get_url_history))