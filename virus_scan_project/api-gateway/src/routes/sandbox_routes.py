from flask import Blueprint
from controllers.sandbox_controller import run_file, get_run_results, get_sandbox_history
from middleware.auth import jwt_required, check_quota

sandbox_bp = Blueprint('sandbox', __name__)

# Route pour exécuter un fichier dans le sandbox
sandbox_bp.route('/run', methods=['POST'])(jwt_required(check_quota(run_file)))

# Route pour récupérer les résultats d'une analyse
sandbox_bp.route('/results/<run_id>', methods=['GET'])(jwt_required(get_run_results))

# Route pour récupérer l'historique des analyses
sandbox_bp.route('/history', methods=['GET'])(jwt_required(get_sandbox_history))