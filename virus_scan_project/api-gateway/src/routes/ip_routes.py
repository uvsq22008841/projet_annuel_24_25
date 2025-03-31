from flask import Blueprint
from controllers.ip_controller import analyze_ip, get_ip_history
from middleware.auth import jwt_required, check_quota

ip_bp = Blueprint('ips', __name__)

# Route pour analyser une adresse IP
ip_bp.route('/analyze', methods=['POST'])(jwt_required(check_quota(analyze_ip)))

# Route pour récupérer l'historique des analyses
ip_bp.route('/history', methods=['GET'])(jwt_required(get_ip_history))