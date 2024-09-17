from datetime import datetime, timedelta

import pytest
from werkzeug.security import generate_password_hash

from ServerSide import create_app, db
from ServerSide.models import User, Quiz


@pytest.fixture()
def app():
    app = create_app('sqlite:///test.sqlite')  # Use a separate test database

    with app.app_context():
        db.create_all()  # Create tables

        yield app  # Provide the app for testing

        # Cleanup
        with app.app_context():
            db.session.remove()
            db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


@pytest.fixture()
def setup_users(app):
    with app.app_context():
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        user = User(
            username='user1',
            email='user1@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

        return admin, user
