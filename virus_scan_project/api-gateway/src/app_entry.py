import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta

from config.config import Config
from middleware.error_handler import register_error_handlers
from routes.auth_routes import auth_bp
from routes.file_routes import file_bp
from routes.url_routes import url_bp
from routes.ip_routes import ip_bp
from routes.sandbox_routes import sandbox_bp
from utils.logger import setup_logger

def create_app(config_name='default'):
    """Initialise et configure l'application Flask"""
    app = Flask(__name__)
    
    # Charger la configuration
    app_config = Config.get_config(config_name)
    app.config.from_object(app_config)
    
    # Configurer CORS
    CORS(app)
    
    # Configurer JWT
    app.config['JWT_SECRET_KEY'] = app_config.JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    jwt = JWTManager(app)
    
    # Configurer le logger
    logger = setup_logger()
    
    # Enregistrer les gestionnaires d'erreurs
    register_error_handlers(app)
    
    # Enregistrer les blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(file_bp, url_prefix='/api/files')
    app.register_blueprint(url_bp, url_prefix='/api/urls')
    app.register_blueprint(ip_bp, url_prefix='/api/ips')
    app.register_blueprint(sandbox_bp, url_prefix='/api/sandbox')
    
    # Route de santé
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'UP', 'service': 'virus-scan-api-gateway'})
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])