/virus_scan_project
  /api-gateway
    /src
      /config
        __init__.py
        config.py           # Configuration globale
        db.py               # Configuration de la base de données
      /controllers          # Contrôleurs pour chaque service
        __init__.py
        auth_controller.py
        file_controller.py
        url_controller.py
        ip_controller.py
        sandbox_controller.py
      /middleware
        __init__.py
        auth.py             # Middleware d'authentification JWT
        error_handler.py    # Gestion des erreurs
        validator.py        # Validation des requêtes
      /models
        __init__.py
        user.py             # Modèle utilisateur
      /routes               # Routes de l'API
        __init__.py
        auth_routes.py
        file_routes.py
        url_routes.py
        ip_routes.py
        sandbox_routes.py
      /services             # Services pour la communication avec les microservices
        __init__.py
        file_service.py
        url_service.py
        ip_service.py
        sandbox_service.py
      /utils                # Utilitaires
        __init__.py
        logger.py
        response_formatter.py
      app.py                # Point d'entrée de l'application
    requirements.txt
    Dockerfile
    docker-compose.yml      # Pour orchestrer tous les services