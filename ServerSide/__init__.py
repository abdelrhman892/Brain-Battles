import os
import logging
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate

db = SQLAlchemy()
mail = Mail()
migrate = Migrate()
load_dotenv()


def create_app():
    app = Flask(__name__)

    # App Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # app password in gmail
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True

    # Configuration for session security
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
    )

    # Logging Configuration
    if not app.debug:
        handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s -  %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    # Register Blueprints
    from .user.auth import auth
    from .user.userMange import user
    from .view import view
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(user, url_prefix='/profile')
    app.register_blueprint(view, url_prefix='/')

    # Create database tables
    with app.app_context():
        db.create_all()

    return app
