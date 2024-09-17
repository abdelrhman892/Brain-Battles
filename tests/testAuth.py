from werkzeug.security import generate_password_hash

from ServerSide import db
from ServerSide.models import User


# Sign-up for test cases
def test_sign_up_success(client):
    response = client.post('/auth/sign-up', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert b'OTP sent to email! Check your inbox.' in response.data


def test_register_invalid_json(client):
    # Test registration with invalid JSON
    response = client.post('/auth/sign-up', json={})
    assert response.status_code == 400
    assert b'Missing JSON in request' in response.data


def test_sign_up_existing_email(client, app):
    with app.app_context():
        # Create a user directly using the model
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            email_verified=True
        )
        db.session.add(user)
        db.session.commit()

    response = client.post('/auth/sign-up', json={
        'username': 'anotheruser',
        'email': 'testuser@example.com',  # Existing email
        'password': 'password123'
    })
    assert response.status_code == 409
    assert b'Email already registered' in response.data


def test_sign_up_invalid_email(client):
    response = client.post('/auth/sign-up', json={
        'username': 'testuser',
        'email': 'invalidemail',  # Invalid email format
        'password': 'password123'
    })
    assert response.status_code == 400
    assert b'Not a valid email address.' in response.data  # Adjust message based on your schema validation


def test_sign_up_weak_password(client):
    response = client.post('/auth/sign-up', json={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password': 'short'  # Weak password
    })
    assert response.status_code == 400
    assert b'Length must be between 7 and 20.' in response.data  # Adjust message based on your schema validation


# Log-in test cases
def test_login_missing_json(client):
    response = client.post('/auth/log-in', json={})
    assert response.status_code == 400
    assert b'Missing JSON in request' in response.data


def test_login_missing_fields(client):
    response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        # Missing password
    })
    assert response.status_code == 400
    assert b'Missing data for required field.' in response.data  # Adjust message based on your schema validation


def test_login_invalid_email(client):
    response = client.post('/auth/log-in', json={
        'email': 'invalidemail',  # Invalid email format
        'password': 'password123'
    })
    assert response.status_code == 400
    assert b'Not a valid email address.' in response.data  # Adjust message based on your schema validation


def test_login_invalid_password(client, app):
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
        )
        db.session.add(user)
        db.session.commit()

        response = client.post('/auth/log-in', json={
            'email': 'testuser@example.com',
            'password': '<PASSWORD>'
        })
        assert response.status_code == 401
        assert b'Incorrect email or password' in response.data


def test_login_email_not_registered(client):
    response = client.post('/auth/log-in', json={
        'email': 'nonexistent@example.com',
        'password': 'password123'
    })
    assert response.status_code == 401
    assert b'Email not registered' in response.data


def test_login_success(client, app):
    # Register the user
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
        )
        db.session.add(user)
        db.session.commit()

    # Log in with the registered user
    response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert b'Login successful!' in response.data
    assert b'Token' in response.data
    assert b'Refresh_token' in response.data


# Log-out test cases
def test_logout_success(client, app):
    # Create a user and log them in to get a token
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

    # Perform login to get a valid token
    login_response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    tokens = login_response.json
    token = tokens['Token']

    # Logout with the valid token
    response = client.get('/auth/log-out', headers={'Authorization': f'{token}'})
    assert response.status_code == 200
    assert b'Logged out successfully!' in response.data

    # Check if the user is inactive
    with app.app_context():
        user = User.query.filter_by(email='testuser@example.com').first()
        assert user is not None
        assert user.is_active == False


def test_logout_invalid_token(client):
    # Attempt to log out with an invalid token
    response = client.get('/auth/log-out', headers={'Authorization': 'invalidtoken'})
    assert response.status_code == 403
    assert b'Invalid token' in response.data


def test_logout_missing_token(client):
    # Attempt to log out without providing a token
    response = client.get('/auth/log-out')
    assert response.status_code == 404
    assert b'Token is missing' in response.data


# Forget password test cases
def test_forgot_password_success(client, app):
    # Create a user to test OTP functionality
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()

    # Request OTP for the registered email
    response = client.get('/auth/forgot-password',
                          query_string={'email': 'testuser@example.com'})
    assert response.status_code == 200
    assert b'OTP sent to email! Check your inbox.' in response.data


def test_forgot_password_email_not_registered(client):
    # Request OTP for an email that does not exist in the database
    response = client.get('/auth/forgot-password',
                          query_string={'email': 'nonexistent@example.com'})
    assert response.status_code == 401
    assert b'Email not registered' in response.data


def test_forgot_password_missing_email(client):
    # Request OTP without providing the email parameter
    response = client.get('/auth/forgot-password')
    assert response.status_code == 404
    assert b'Missing argument in request' in response.data


def test_forgot_password_Invalid_email_format(client):
    # Request OTP with Invalid email format
    response = client.get('/auth/forgot-password', query_string={'email': 'testuser@example'})
    assert response.status_code == 400
    assert b'Invalid email format' in response.data


# Refresh token test cases
def test_refresh_token_success(client, app):
    # Create a user and simulate login to generate a refresh token
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

        # Mock the refresh token verification decorator to simulate a valid token
        response = client.post('/auth/log-in', json={
            'email': 'testuser@example.com',
            'password': 'password123'
        })
        tokens = response.json
        token = tokens['Refresh_token']
        # Simulate a valid refresh token request
        response = client.get('/auth/refresh_token', headers={'Authorization': f'{token}'})
        assert response.status_code == 200
        assert b'Token refreshed successfully.' in response.data
        assert b'Token' in response.data


def test_refresh_token_invalid_token(client):
    # Simulate a refresh token request with an invalid token
    response = client.get('/auth/refresh_token', headers={'Authorization': 'invalid_refresh_token'})
    assert response.status_code == 403
    assert b'Invalid token' in response.data


def test_refresh_token_missing_token(client):
    # Simulate a refresh token request without an Authorization header
    response = client.get('/auth/refresh_token')
    assert response.status_code == 404
    assert b'Token is missing' in response.data