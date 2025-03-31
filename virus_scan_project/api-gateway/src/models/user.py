import psycopg2
import psycopg2.extras
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from config.config import Config
from config.db import get_db_connection

logger = logging.getLogger(__name__)

class User:
    """Modèle pour la gestion des utilisateurs"""
    
    def __init__(self, user_id=None, username=None, email=None, password=None, 
                 role='user', quota_used=0, quota_limit=100, 
                 created_at=None, updated_at=None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.quota_used = quota_used
        self.quota_limit = quota_limit
        self.created_at = created_at
        self.updated_at = updated_at
    
    @staticmethod
    def get_by_id(user_id):
        """Récupère un utilisateur par son ID"""
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE user_id = %s",
                    (user_id,)
                )
                user_data = cursor.fetchone()
                
                if user_data:
                    return User(
                        user_id=user_data['user_id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password=user_data['password_hash'],
                        role=user_data['role'],
                        quota_used=user_data['quota_used'],
                        quota_limit=user_data['quota_limit'],
                        created_at=user_data['created_at'],
                        updated_at=user_data['updated_at']
                    )
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_by_username(username):
        """Récupère un utilisateur par son nom d'utilisateur"""
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE username = %s",
                    (username,)
                )
                user_data = cursor.fetchone()
                
                if user_data:
                    return User(
                        user_id=user_data['user_id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password=user_data['password_hash'],
                        role=user_data['role'],
                        quota_used=user_data['quota_used'],
                        quota_limit=user_data['quota_limit'],
                        created_at=user_data['created_at'],
                        updated_at=user_data['updated_at']
                    )
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_by_email(email):
        """Récupère un utilisateur par son email"""
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (email,)
                )
                user_data = cursor.fetchone()
                
                if user_data:
                    return User(
                        user_id=user_data['user_id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password=user_data['password_hash'],
                        role=user_data['role'],
                        quota_used=user_data['quota_used'],
                        quota_limit=user_data['quota_limit'],
                        created_at=user_data['created_at'],
                        updated_at=user_data['updated_at']
                    )
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def save(self):
        """Sauvegarde l'utilisateur dans la base de données"""
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                if self.user_id:
                    # Mise à jour d'un utilisateur existant
                    cursor.execute(
                        """
                        UPDATE users SET 
                            username = %s,
                            email = %s,
                            password_hash = %s,
                            role = %s,
                            quota_used = %s,
                            quota_limit = %s,
                            updated_at = %s
                        WHERE user_id = %s
                        RETURNING user_id
                        """,
                        (
                            self.username,
                            self.email,
                            self.password,
                            self.role,
                            self.quota_used,
                            self.quota_limit,
                            datetime.now(),
                            self.user_id
                        )
                    )
                else:
                    # Insertion d'un nouvel utilisateur
                    cursor.execute(
                        """
                        INSERT INTO users (
                            username, email, password_hash, role, 
                            quota_used, quota_limit, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING user_id
                        """,
                        (
                            self.username,
                            self.email,
                            self.password,
                            self.role,
                            self.quota_used,
                            self.quota_limit,
                            datetime.now(),
                            datetime.now()
                        )
                    )
                
                self.user_id = cursor.fetchone()[0]
                conn.commit()
                return self.user_id
                
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Erreur lors de la sauvegarde de l'utilisateur: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def update_quota(self, amount=1):
        """Met à jour le quota utilisé par l'utilisateur"""
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users SET 
                        quota_used = quota_used + %s,
                        updated_at = %s
                    WHERE user_id = %s
                    RETURNING quota_used
                    """,
                    (amount, datetime.now(), self.user_id)
                )
                
                self.quota_used = cursor.fetchone()[0]
                conn.commit()
                return self.quota_used
                
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Erreur lors de la mise à jour du quota: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def to_dict(self):
        """Convertit l'utilisateur en dictionnaire"""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'quota_used': self.quota_used,
            'quota_limit': self.quota_limit,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @staticmethod
    def hash_password(password):
        """Génère un hash du mot de passe"""
        return generate_password_hash(password)
    
    def check_password(self, password):
        """Vérifie si le mot de passe correspond au hash stocké"""
        return check_password_hash(self.password, password)