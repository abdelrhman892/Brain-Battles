from werkzeug.security import generate_password_hash

from ServerSide import db
from ServerSide.models import User, Quiz


def test_add_quiz_invalid_data(client, app):
    with app.app_context():
        # Create a user
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the user
        login_response = client.post('/auth/log-in', json={
            'email': 'testuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

    # Send request with invalid data (e.g., missing title)
    response = client.post('/add_quiz', headers={
        'Authorization': f'{token}'
    }, json={
        'description': 'This is a test quiz description.',
        'visibility': 'public',
        'last_editable_at': '2 hours',
        'expiration': '1 day',
        'timer': '30 minutes'
    })

    # Assert the response for invalid data
    assert response.status_code == 401
    # Ensure the error is related to missing title
    assert 'title' in response.json['message']


def test_add_quiz_missing_data(client, app):
    with app.app_context():
        # Create a user
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

    # Simulate login to get a token for the user
    login_response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    token = login_response.json['Token']
    response = client.post('/add_quiz', headers={'Authorization': f'{token}'}, json={})
    assert response.status_code == 404
    assert response.json['message'] == 'Missing data'


def test_add_quiz_invalid_field_data(client, app):
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

    login_response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    token = login_response.json['Token']
    invalid_data = {
        'title': '',
        'description': 'Short quiz',
        'visibility': 'public',  # Assuming this is valid, but other fields missing/invalid
    }
    response = client.post('/add_quiz', headers={'Authorization': f'{token}'}, json=invalid_data)
    assert response.status_code == 401  # Validation error
    assert 'title' in response.json['message']  # The missing or invalid field should appear in the error


def test_add_quiz_success(client, app):
    with app.app_context():
        user = User(
            username='testuser',
            email='testuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

    login_response = client.post('/auth/log-in', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    token = login_response.json['Token']
    valid_data = {
        'title': 'Test Quiz',
        'description': 'A quiz for testing purposes.',
        'visibility': 'private',
        'last_editable_at': '1 day',
        'expiration': '2 days',
        'timer': '30 minutes'
    }
    response = client.post('/add_quiz',
                           headers={'Authorization': f'{token}'},
                           json=valid_data)
    assert response.status_code == 201
    assert response.json['message'] == 'Quiz successfully added'
    assert 'quiz' in response.json  # Check that the quiz data is returned


def test_invalid_email_format_for_quizzes(client, setup_users):
    # Simulate login to get a token for admin
    login_response = client.post('/auth/log-in', json={
        'email': 'admin@example.com',
        'password': 'password123'
    })
    token = login_response.json['Token']

    # Fetch quizzes with invalid email format
    response = client.get('/get_quizzes', headers={
        'Authorization': f'{token}',
        'Email': 'invalidemailformat'
    })

    assert response.status_code == 400
    assert response.json['message'] == 'Invalid email format'


def test_non_existent_user_for_quizzes(client, setup_users):
    # Simulate login to get a token for admin
    login_response = client.post('/auth/log-in', json={
        'email': 'admin@example.com',
        'password': 'password123'
    })
    token = login_response.json['Token']

    # Fetch quizzes for a non-existent user
    response = client.get('/get_quizzes', headers={
        'Authorization': f'{token}',
        'Email': 'nonexistent@example.com'
    })

    assert response.status_code == 404
    assert response.json['message'] == 'User does not exist'


def test_get_quiz_by_id_success(client, app):
    with app.app_context():
        # Create admin and regular users
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        regular_user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin_user)
        db.session.add(regular_user)
        db.session.commit()

        # Create a quiz for the regular user
        quiz = Quiz(
            id='test-quiz-id',
            title='Sample Quiz',
            description='A sample quiz description',
            user_id=regular_user.id,
            timer=60
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with valid email and quiz ID
        response = client.get('/get_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'regularuser@example.com',
            'X-Quiz-ID': quiz.id
        })

        # Assert successful response
        assert response.status_code == 200
        assert 'Successfully retrieved the quiz.' in response.json['message']
        assert response.json['quiz']['title'] == 'Sample Quiz'


def test_get_quiz_by_id_admin_invalid_email_format(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with invalid email format
        response = client.get('/get_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'invalid-email-format',
            'X-Quiz-ID': 'some-quiz-id'
        })

        # Assert error response for invalid email format
        assert response.status_code == 400
        assert 'Invalid email format' in response.json['message']


def test_get_quiz_by_id_admin_non_existent_user_email(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with a non-existent user email
        response = client.get('/get_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'nonexistent@example.com',
            'X-Quiz-ID': 'some-quiz-id'
        })

        # Assert error response for non-existent user
        assert response.status_code == 404
        assert 'User does not exist' in response.json['message']


def test_get_quiz_by_id_user_missing_quiz_id(client, app):
    with app.app_context():
        # Create a regular user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the regular user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request without 'X-Quiz-ID'
        response = client.get('/get_quiz', headers={
            'Authorization': f'{token}'
        })

        # Assert error response for missing quiz ID
        assert response.status_code == 400
        assert 'Missing token or quiz_id' in response.json['message']


def test_get_quiz_by_id_user_invalid_token(client, app):
    with app.app_context():
        # Create a regular user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the regular user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Simulate an invalid token scenario
        invalid_token = token + 'invalid'

        # Send request with an invalid token
        response = client.get('/get_quiz', headers={
            'Authorization': f'Bearer {invalid_token}',
            'X-Quiz-ID': 'some-quiz-id'
        })

        # Assert error response for invalid token
        assert response.status_code == 403
        assert 'Invalid token' in response.json['message']


def test_get_all_quizzes_admin(client, app):
    with app.app_context():
        # Create an admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Create some quizzes
        quiz1 = Quiz(
            id='quiz-1',
            title='Quiz One',
            description='Description of Quiz One',
            user_id=admin_user.id,
            timer=30
        )
        quiz2 = Quiz(
            id='quiz-2',
            title='Quiz Two',
            description='Description of Quiz Two',
            user_id=admin_user.id,
            timer=60
        )
        db.session.add(quiz1)
        db.session.add(quiz2)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to get all quizzes
        response = client.get('/quizzes', headers={
            'Authorization': f'{token}'
        })

        # Assert successful response
        assert response.status_code == 200
        assert 'Quizzes fetched successfully' in response.json['message']
        assert len(response.json['quizzes']) == 2
        assert response.json['quizzes'][0]['title'] == 'Quiz One'
        assert response.json['quizzes'][1]['title'] == 'Quiz Two'


def test_get_all_quizzes_user_access_denied(client, app):
    with app.app_context():
        # Create a regular user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the regular user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to get all quizzes
        response = client.get('/quizzes', headers={
            'Authorization': f'{token}'
        })

        # Assert access denied response
        assert response.status_code == 403
        assert 'Access denied' in response.json['message']


def test_get_all_quizzes_moderator_access_denied(client, app):
    with app.app_context():
        # Create a regular user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='moderator'
        )
        db.session.add(user)
        db.session.commit()

        # Simulate login to get a token for the regular user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to get all quizzes
        response = client.get('/quizzes', headers={
            'Authorization': f'{token}'
        })

        # Assert access denied response
        assert response.status_code == 403
        assert 'Access denied' in response.json['message']


def test_get_all_quizzes_admin_no_quizzes(client, app):
    with app.app_context():
        # Create an admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to get all quizzes when no quizzes exist
        response = client.get('/quizzes', headers={
            'Authorization': f'{token}'
        })

        # Assert no quizzes found response
        assert response.status_code == 404
        assert 'No quizzes found' in response.json['message']


def test_delete_quiz_admin_success(client, app):
    with app.app_context():
        # Create admin and regular users
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        regular_user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin_user)
        db.session.add(regular_user)
        db.session.commit()

        # Create a quiz for the regular user
        quiz = Quiz(
            id='quiz-to-delete',
            title='Quiz to Delete',
            description='This quiz will be deleted',
            user_id=regular_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to delete the quiz
        response = client.delete('/delete_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'regularuser@example.com',
            'X-Quiz-ID': quiz.id
        })

        # Assert successful deletion
        assert response.status_code == 200
        assert 'Successfully deleted the quiz.' in response.json['message']

        # Verify that the quiz was actually deleted
        deleted_quiz = Quiz.query.filter_by(id=quiz.id).first()
        assert deleted_quiz is None


def test_delete_quiz_admin_invalid_email_format(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Create a quiz
        quiz = Quiz(
            id='quiz-to-delete',
            title='Quiz to Delete',
            description='This quiz will be deleted',
            user_id=admin_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with invalid email format
        response = client.delete('/delete_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'invalid-email-format',
            'X-Quiz-ID': quiz.id
        })

        # Assert error response for invalid email format
        assert response.status_code == 400
        assert 'Invalid email format' in response.json['message']


def test_delete_quiz_admin_non_existent_user_email(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Create a quiz
        quiz = Quiz(
            id='quiz-to-delete',
            title='Quiz to Delete',
            description='This quiz will be deleted',
            user_id=admin_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with a non-existent user email
        response = client.delete('/delete_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'nonexistent@example.com',
            'X-Quiz-ID': quiz.id
        })

        # Assert error response for non-existent user
        assert response.status_code == 404
        assert 'User does not exist' in response.json['message']


def test_delete_quiz_user_success(client, app):
    with app.app_context():
        # Create a user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Create a quiz for the user
        quiz = Quiz(
            id='quiz-to-delete',
            title='Quiz to Delete',
            description='This quiz will be deleted',
            user_id=user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to delete the quiz
        response = client.delete('/delete_quiz', headers={
            'Authorization': f'{token}',
            'X-Quiz-ID': quiz.id
        })

        # Assert successful deletion
        assert response.status_code == 200
        assert 'Successfully deleted the quiz.' in response.json['message']

        # Verify that the quiz was actually deleted
        deleted_quiz = Quiz.query.filter_by(id=quiz.id).first()
        assert deleted_quiz is None


def test_delete_quiz_user_other_users_quiz(client, app):
    with app.app_context():
        # Create two users
        user1 = User(
            username='user1',
            email='user1@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        user2 = User(
            username='user2',
            email='user2@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Create a quiz for user1
        quiz = Quiz(
            id='quiz-to-delete',
            title='Quiz to Delete',
            description='This quiz will be deleted',
            user_id=user1.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for user2
        login_response = client.post('/auth/log-in', json={
            'email': 'user2@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to delete user1's quiz
        response = client.delete('/delete_quiz', headers={
            'Authorization': f'{token}',
            'X-Quiz-ID': quiz.id
        })

        # Assert error response for attempting to delete another user's quiz
        assert response.status_code == 404
        assert 'Quiz not found' in response.json['message']


def test_update_quiz_admin_success(client, app):
    with app.app_context():
        # Create admin and regular users
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        regular_user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(admin_user)
        db.session.add(regular_user)
        db.session.commit()

        # Create a quiz for the regular user
        quiz = Quiz(
            id='quiz-to-update',
            title='Old Title',
            description='Old description',
            user_id=regular_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to update the quiz
        response = client.patch('/update_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'regularuser@example.com',
            'X-Quiz-ID': quiz.id
        }, json={
            'title': 'Updated Title',
            'description': 'Updated description'
        })

        # Assert successful update
        assert response.status_code == 200
        assert 'Quiz updated successfully.' in response.json['message']
        assert response.json['updated_fields']['title'] == 'Updated Title'

        # Verify the quiz was updated
        updated_quiz = Quiz.query.filter_by(id=quiz.id).first()
        assert updated_quiz.title == 'Updated Title'
        assert updated_quiz.description == 'Updated description'


def test_update_quiz_admin_invalid_email_format(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Create a quiz
        quiz = Quiz(
            id='quiz-to-update',
            title='Old Title',
            description='Old description',
            user_id=admin_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with invalid email format
        response = client.patch('/update_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'invalid-email-format',
            'X-Quiz-ID': quiz.id
        }, json={
            'title': 'Updated Title'
        })

        # Assert error response for invalid email format
        assert response.status_code == 400
        assert 'Invalid email format' in response.json['message']


def test_update_quiz_admin_non_existent_user_email(client, app):
    with app.app_context():
        # Create admin user
        admin_user = User(
            username='adminuser',
            email='adminuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()

        # Create a quiz
        quiz = Quiz(
            id='quiz-to-update',
            title='Old Title',
            description='Old description',
            user_id=admin_user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the admin user
        login_response = client.post('/auth/log-in', json={
            'email': 'adminuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request with non-existent user email
        response = client.patch('/update_quiz', headers={
            'Authorization': f'{token}',
            'Email': 'nonexistent@example.com',
            'X-Quiz-ID': quiz.id
        }, json={
            'title': 'Updated Title'
        })

        # Assert error response for non-existent user
        assert response.status_code == 404
        assert 'User does not exist' in response.json['message']


def test_update_quiz_user_success(client, app):
    with app.app_context():
        # Create a user
        user = User(
            username='regularuser',
            email='regularuser@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user)
        db.session.commit()

        # Create a quiz for the user
        quiz = Quiz(
            id='quiz-to-update',
            title='Old Title',
            description='Old description',
            user_id=user.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for the user
        login_response = client.post('/auth/log-in', json={
            'email': 'regularuser@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to update the quiz
        response = client.patch('/update_quiz', headers={
            'Authorization': f'{token}',
            'X-Quiz-ID': quiz.id
        }, json={
            'title': 'Updated Title',
            'description': 'Updated description'
        })

        # Assert successful update
        assert response.status_code == 200
        assert 'Quiz updated successfully.' in response.json['message']
        assert response.json['updated_fields']['title'] == 'Updated Title'

        # Verify the quiz was updated
        updated_quiz = Quiz.query.filter_by(id=quiz.id).first()
        assert updated_quiz.title == 'Updated Title'
        assert updated_quiz.description == 'Updated description'


def test_update_quiz_user_other_users_quiz(client, app):
    with app.app_context():
        # Create two users
        user1 = User(
            username='user1',
            email='user1@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        user2 = User(
            username='user2',
            email='user2@example.com',
            password=generate_password_hash('password123', method='pbkdf2:sha256'),
            role='user'
        )
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Create a quiz for user1
        quiz = Quiz(
            id='quiz-to-update',
            title='Old Title',
            description='Old description',
            user_id=user1.id,
            timer=30
        )
        db.session.add(quiz)
        db.session.commit()

        # Simulate login to get a token for user2
        login_response = client.post('/auth/log-in', json={
            'email': 'user2@example.com',
            'password': 'password123'
        })
        token = login_response.json['Token']

        # Send request to update user1's quiz
        response = client.patch('/update_quiz', headers={
            'Authorization': f'{token}',
            'X-Quiz-ID': quiz.id
        }, json={
            'title': 'Updated Title'
        })

        # Assert error response for attempting to update another user's quiz
        assert response.status_code == 404
        assert 'Quiz not found' in response.json['message']
