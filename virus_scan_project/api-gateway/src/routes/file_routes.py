from flask import Blueprint
from controllers.file_controller import analyze_file, lookup_hash, get_file_history
from middleware.auth import jwt_required, check_quota

file_bp = Blueprint('files', __name__)

# Route pour analyser un fichier
file_bp.route('/analyze', methods=['POST'])(jwt_required(check_quota(analyze_file)))

# Route pour vérifier un hash
file_bp.route('/lookup', methods=['POST'])(jwt_required(lookup_hash))

# Route pour récupérer l'historique des analyses
file_bp.route('/history', methods=['GET'])(jwt_required(get_file_history))