from werkzeug.security import generate_password_hash
from ServerSide import db
from ServerSide.models import User


# Test successful user creation
def test_add_user_success(client, app):
    # Create a mock admin user to authenticate
    with app.app_context():
        admin_user = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('adminpass', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Perform login to get a valid token
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'adminpass'
        })
        token = login_response.json['Token']

        # Try to add a new user
        response = client.post('/profile/add_user', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password123'
        }, headers={'Authorization': f'{token}'})

        assert response.status_code == 201
        assert b'User created successfully' in response.data


# Test creating a user that already exists
def test_add_user_exists(client, app):
    with app.app_context():
        # Create a user directly in the database
        existing_user = User(
            username='existinguser',
            email='existing@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256')
        )
        db.session.add(existing_user)
        db.session.commit()

        # Login as admin
        admin_user = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('adminpass', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'adminpass'
        })
        token = login_response.json['Token']

        # Try to add a new user with the same email
        response = client.post('/profile/add_user', json={
            'username': 'newuser',
            'email': 'existing@example.com',  # Existing email
            'password': 'password123'
        }, headers={'Authorization': f'{token}'})

        assert response.status_code == 409
        assert b'User already exists' in response.data


# Test access denied for non-admin users
def test_add_user_access_denied(client, app):
    with app.app_context():
        # Create a non-admin user
        user = User(
            username='regularuser',
            email='user@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Login as the non-admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'user@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Try to add a new user
        response = client.post('/profile/add_user', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password123'
        }, headers={'Authorization': f'{token}'})

        assert response.status_code == 401
        assert b'Access denied' in response.data


# Test invalid data (schema validation)
def test_add_user_invalid_data(client, app):
    with app.app_context():
        # Create a mock admin user to authenticate
        admin_user = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('adminpass', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Perform login to get a valid token
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'adminpass'
        })
        token = login_response.json['Token']

        # Try to add a new user with invalid data (missing username)
        response = client.post('/profile/add_user', json={
            'email': 'newuser@example.com',
            'password': 'password123'
        }, headers={'Authorization': f'{token}'})

        assert response.status_code == 403
        assert b'username' in response.data  # Schema error message


def test_get_users_access_denied(client, app):
    with app.app_context():
        # Create a user with 'user' role
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token
        login_response = client.post('/auth/log-in', json={
            'email': 'testuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to fetch users with 'user' role
        response = client.get('/profile/get_users', headers={'Authorization': f'{token}'})

        assert response.status_code == 401
        assert b'Access denied' in response.data


def test_get_users_success(client, app):
    with app.app_context():
        # Create an admin user and another user
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the admin
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to fetch users with 'admin' role
        response = client.get('/profile/get_users', headers={'Authorization': f'{token}'})

        assert response.status_code == 200
        data = response.json
        assert data['message'] == 'Successfully fetched all users.'
        assert len(data['users']) == 2  # adminuser + testuser
        assert data['users'][0]['username'] == 'adminuser'
        assert data['users'][1]['username'] == 'testuser'


def test_admin_fetches_another_user(client, app):
    with app.app_context():
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        user = User(
            username='testuser',
            email='user@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.get('/profile/get_user', headers={
            'Authorization': f'{token}',
            'Email': 'user@example.com'
        })

        assert response.status_code == 200
        assert response.json['user']['email'] == 'user@example.com'


def test_regular_user_fetches_own_details(client, app):
    with app.app_context():
        user = User(
            username='regularuser',
            email='regular@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'regular@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.get('/profile/get_user', headers={
            'Authorization': f'{token}'
        })

        assert response.status_code == 200
        assert response.json['user']['email'] == 'regular@example.com'


def test_admin_fetches_nonexistent_user(client, app):
    with app.app_context():
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.get('/profile/get_user', headers={
            'Authorization': f'{token}',
            'Email': 'nonexistent@example.com'
        })

        assert response.status_code == 404
        assert response.json['message'] == 'User does not exist'


def test_admin_provides_invalid_email_format(client, app):
    with app.app_context():
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.get('/profile/get_user', headers={
            'Authorization': f'{token}',
            'Email': 'invalid-email-format'
        })

        assert response.status_code == 401
        assert response.json['message'] == 'Invalid email format'


def test_admin_updates_user_info(client, app):
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

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.patch('/profile/update_user', headers={
            'Authorization': f'{token}',
            'Email': 'user1@example.com'
        }, json={
            'username': 'new_username'
        })

        assert response.status_code == 200
        assert response.json['message'] == 'User updated successfully.'
        assert response.json['updated_fields']['username'] == 'new_username'


def test_regular_user_updates_own_info(client, app):
    with app.app_context():
        user = User(
            username='regularuser',
            email='regular@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'regular@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.patch('/profile/update_user', headers={
            'Authorization': f'{token}'
        }, json={
            'username': 'new_regularuser'
        })

        assert response.status_code == 200
        assert response.json['message'] == 'User updated successfully.'
        assert response.json['updated_fields']['username'] == 'new_regularuser'


def test_admin_provides_invalid_email_format_update_user(client, app):
    with app.app_context():
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.patch('/profile/update_user', headers={
            'Authorization': f'{token}',
            'Email': 'invalid-email-format'
        }, json={
            'username': 'new_username'
        })

        assert response.status_code == 401
        assert response.json['message'] == 'Invalid email format'


def test_user_update_password_with_same_old_password(client, app):
    with app.app_context():
        user = User(
            username='user1',
            email='user1@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        login_response = client.post('/auth/log-in', json={
            'email': 'user1@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        response = client.patch('/profile/update_user', headers={
            'Authorization': f'{token}'
        }, json={
            'password': 'password123'
        })

        assert response.status_code == 400
        assert response.json['message'] == 'This password is the same as your old password.'


def test_delete_user(client, app):
    with app.app_context():
        # Create an admin user
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

        # Simulate login to get a token for the admin
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to delete the user
        response = client.delete('/profile/delete_user', headers={
            'Authorization': f'{token}',
            'email': 'user1@example.com'
        })

        assert response.status_code == 200
        assert response.json['message'] == 'User deleted successfully.'


def test_delete_user_not_found(client, app):
    with app.app_context():
        # Create an admin user
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

        # Simulate login to get a token for the admin
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to delete a user
        response = client.delete('/profile/delete_user', headers={
            'Authorization': f'{token}',
            'email': 'user1@example.com'
        })

        assert response.status_code == 404
        assert response.json['message'] == 'User does not exist.'


def test_delete_user_access_denied(client, app):
    with app.app_context():
        # Create a non-admin user
        non_admin = User(
            username='user1',
            email='user1@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(non_admin)
        db.session.commit()

        # Simulate login to get a token for the non-admin
        login_response = client.post('/auth/log-in', json={
            'email': 'user1@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to delete a user
        response = client.delete('/profile/delete_user', headers={
            'Authorization': f'{token}',
            'email': 'user1@example.com'
        })

        assert response.status_code == 401
        assert response.json['message'] == 'Access denied'


def test_delete_user_invalid_email(client, app):
    with app.app_context():
        # Create an admin user
        admin = User(
            username='adminuser',
            email='admin@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

        # Simulate login to get a token for the admin
        login_response = client.post('/auth/log-in', json={
            'email': 'admin@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Attempt to delete a user with invalid email format
        response = client.delete('/profile/delete_user', headers={
            'Authorization': f'{token}',
            'email': 'invalid-email-format'
        })

        assert response.status_code == 401
        assert response.json['message'] == 'Invalid email format'

        # Test with missing email header
        response = client.delete('/profile/delete_user', headers={
            'Authorization': f'{token}'
        })

        assert response.status_code == 401
        assert response.json['message'] == 'Invalid email format'
