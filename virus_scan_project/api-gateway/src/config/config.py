import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis le fichier .env s'il existe
load_dotenv()

class BaseConfig:
    """Configuration de base"""
    DEBUG = False
    TESTING = False
    
    # Clé secrète pour JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')
    
    # Configuration de la base de données
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 5432))
    DB_NAME = os.environ.get('DB_NAME', 'VirusScan')
    DB_USER = os.environ.get('DB_USER', 'your_username')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'your_password')
    
    # URLs des services
    FILE_ANALYSIS_URL = os.environ.get('FILE_ANALYSIS_URL', 'http://localhost:5001')
    FILE_ANALYSIS_TIMEOUT = int(os.environ.get('FILE_ANALYSIS_TIMEOUT', 30))
    
    URL_ANALYSIS_URL = os.environ.get('URL_ANALYSIS_URL', 'http://localhost:5002')
    URL_ANALYSIS_TIMEOUT = int(os.environ.get('URL_ANALYSIS_TIMEOUT', 30))
    
    IP_ANALYSIS_URL = os.environ.get('IP_ANALYSIS_URL', 'http://localhost:5003')
    IP_ANALYSIS_TIMEOUT = int(os.environ.get('IP_ANALYSIS_TIMEOUT', 30))
    
    SANDBOX_URL = os.environ.get('SANDBOX_URL', 'http://localhost:5004')
    SANDBOX_TIMEOUT = int(os.environ.get('SANDBOX_TIMEOUT', 60))
    
    # Configuration pour l'upload de fichiers
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB
    ALLOWED_EXTENSIONS = os.environ.get('ALLOWED_FILE_TYPES', 
                                       '.exe,.dll,.pdf,.doc,.docx,.xls,.xlsx,.js,.vbs,.bat,.ps1,.jar').split(',')


class DevelopmentConfig(BaseConfig):
    """Configuration de développement"""
    DEBUG = True


class TestingConfig(BaseConfig):
    """Configuration de test"""
    TESTING = True
    DEBUG = True
    
    # Utiliser une base de données de test
    DB_NAME = 'virus_scan_test'


class ProductionConfig(BaseConfig):
    """Configuration de production"""
    pass


class Config:
    """Classe utilitaire pour récupérer la configuration"""
    @staticmethod
    def get_config(config_name='default'):
        config_map = {
            'development': DevelopmentConfig,
            'testing': TestingConfig,
            'production': ProductionConfig,
            'default': DevelopmentConfig
        }
        
        return config_map.get(config_name, DevelopmentConfig)