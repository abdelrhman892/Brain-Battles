import pytest
from ServerSide import create_app, db


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
