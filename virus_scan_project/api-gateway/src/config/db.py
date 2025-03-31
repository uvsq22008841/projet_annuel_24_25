import psycopg2
import logging
from config.config import Config

logger = logging.getLogger(__name__)

def get_db_connection():
    """Établit une connexion à la base de données PostgreSQL"""
    try:
        config = Config.get_config()
        connection = psycopg2.connect(
            host=config.DB_HOST,
            port=config.DB_PORT,
            database=config.DB_NAME,
            user=config.DB_USER,
            password=config.DB_PASSWORD
        )
        return connection
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {str(e)}")
        raise

def init_db():
    """Initialise la base de données avec les tables nécessaires"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Création de la table des utilisateurs si elle n'existe pas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    quota_used INTEGER NOT NULL DEFAULT 0,
                    quota_limit INTEGER NOT NULL DEFAULT 100,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            ''')
            
            # Autres tables nécessaires pour l'API Gateway
            
            conn.commit()
            logger.info("Initialisation de la base de données réussie")
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Erreur lors de l'initialisation de la base de données: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()