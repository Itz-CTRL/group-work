import os
from flask import Flask
from dotenv import load_dotenv

load_dotenv()

def create_app():
    # Use Flask default template_folder ('templates' inside the app package dir)
    app = Flask(__name__)

    # Configuration
    app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')
    app.config['ADMIN_SECRET'] = os.environ.get('ADMIN_SECRET', 'adminpass')
    app.config['ADMIN_HOST'] = os.environ.get('ADMIN_HOST')

    # Database setup
    from .models import configure_db, init_db
    configure_db(app)

    # Initialize database tables
    with app.app_context():
        init_db()

    # Register admin blueprint
    from .routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    # Register student routes (page + API routes at root level)
    from .routes.student import register_routes
    register_routes(app)

    return app
