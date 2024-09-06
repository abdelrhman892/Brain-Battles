import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate

db = SQLAlchemy()
mail = Mail()
migrate = Migrate()


def create_app():
    app = Flask(__name__)

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

    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    from .auth import auth

    app.register_blueprint(auth, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app
