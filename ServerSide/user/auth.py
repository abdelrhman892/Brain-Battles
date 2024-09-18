import logging
from types import NoneType

from flask import Blueprint, request, session, current_app
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from ServerSide import db, mail
from ServerSide.models import User
from ServerSide.validtionModels import SignupSchema, LoginSchema
from marshmallow.exceptions import ValidationError
from ServerSide.helperFuncs import message_response, generate_otp, generate_jwt_token, refresh_token_required
from ServerSide.helperFuncs import token_required, generate_long_token, invalid_email_format

auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['POST'])
def register():
    try:
        # Initialize the schema for validating sign-up data
        schema = SignupSchema()

        try:
            json_date = request.json
            # Check if json is existed
            if not json_date:
                return message_response('Missing JSON in request', 400)

            # Load and validate incoming JSON data using the schema
            data = schema.load(json_date)

        except ValidationError as err:
            # Return validation errors with a 400 Bad Request status
            return message_response(err.messages, 400)

        username = data['username']
        email = data['email']
        password = data['password']

        # Check if the email is already registered in the database
        if User.query.filter_by(email=email).first():
            # Return an error message if the email is already in use
            return message_response('Email already registered', 409)

        if User.query.filter_by(username=username).first():
            return message_response('Username already in use', 409)

        # Generate a One Time Password (OTP) and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['email'] = email
        session['username'] = username
        session['password'] = generate_password_hash(password, method='pbkdf2:sha256')

        # Prepare and send an OTP email to the user
        msg = Message('Brain-Battles password assistance',
                      sender=current_app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = (f'To authenticate, please use the following One Time Password (OTP):\n'
                    f'Your OTP code is: {otp}\n'
                    f'Don\'t share this OTP with anyone. Our customer service team will never ask you\n'
                    f'for your password, OTP, credit card, or banking info.\n\n'
                    f'We hope to see you again soon.')

        mail.send(msg)
        return message_response('OTP sent to email! Check your inbox.', 200)

    except Exception as e:
        return message_response(str(e), 500)


@auth.route('/verify_otp', methods=['POST'])
def verify_otp():
    # Retrieve the OTP from the request headers
    otp = request.headers.get('OTP')

    # Check if OTP was provided in the request
    if not otp:
        return message_response('Missing OTP header', 400)

    # Retrieve the OTP stored in the session for verification
    session_otp = session.get('otp')

    # Verify if the provided OTP matches the one stored in the session
    if session_otp == otp:
        try:
            # Retrieve other user details from the session
            session_email = session.get('email')
            session_username = session.get('username')
            session_password = session.get('password')

            # Create a new User instance with the retrieved details
            user = User(
                email=session_email,
                username=session_username,
                email_verified=True,  # Mark the email as verified
                password=session_password
            )

            # Add the new user to the database and commit the transaction
            db.session.add(user)
            db.session.commit()

            # Clear session data after successful account creation
            session.clear()

            # Return a success response
            return message_response('Account created successfully!', 201)

        except Exception as e:
            # Return a server error response if any exception occurs
            return message_response(str(e), 500)
    else:
        # Return an error response if the OTP is incorrect
        return message_response('Invalid OTP', 400)


@auth.route('/log-in', methods=['POST'])
def login():
    try:
        if not request.json:
            return message_response('Missing JSON in request', 400)

        schema = LoginSchema()
        try:
            date = schema.load(request.json)
        except ValidationError as err:
            return message_response(err.messages, 400)

        email = date['email']
        password = date['password']

        user = User.query.filter_by(email=email).first()
        if not user:
            return message_response('Email not registered', 401)

        if user:
            if check_password_hash(user.password, password):
                try:
                    # Make user active
                    user.is_active = True
                    db.session.commit()
                    # Generate JWT tokens (access and refresh)
                    token = generate_jwt_token(user=user)
                    refresh_token = generate_long_token(user=user)
                    return message_response(
                        'Login successful!',
                        200,
                        Token=token,
                        Refresh_token=refresh_token
                    )

                except Exception as e:
                    # Log any exceptions that occur during the token generation process
                    logging.error(f"Error during login: {e}")
                    return message_response(str(e), 500)
            else:
                logging.error(f'incorrect email or password')
                return message_response('Incorrect email or password', 401)
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return message_response(str(e), 500)


@auth.route('/log-out', methods=['GET'])
@token_required
def logout(current_user):
    try:
        current_user.is_active = False
        db.session.commit()
        return message_response('Logged out successfully!', 200)
    except NoneType as e:
        logging.error(f"Error during logout: {e}")
        return message_response(str(e), 500)


@auth.route('/forgot-password', methods=['GET'])
def forgot_password():
    try:
        data = request.args
        if not data:
            return message_response('Missing argument in request', 404)
        email = data['email']
        if invalid_email_format(email=email):
            return message_response('Invalid email format', 400)
        user = User.query.filter_by(email=email).first()
        if not user:
            return message_response('Email not registered', 401)
        # Generate a One Time Password (OTP) and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['email'] = email
        # Prepare and send an OTP email to the user
        msg = Message('Brain-Battles password assistance',
                      sender=current_app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = (f'To authenticate, please use the following One Time Password (OTP):\n'
                    f'Your OTP code is: {otp}\n'
                    f'Don\'t share this OTP with anyone. Our customer service team will never ask you\n'
                    f'for your password, OTP, credit card, or banking info.\n\n'
                    f'We hope to see you again soon.')

        mail.send(msg)
        return message_response('OTP sent to email! Check your inbox.', 200)
    except Exception as e:
        logging.error(str(e))


@auth.route('/reset-password', methods=['PATCH'])
def reset_password():
    try:
        # Retrieve the OTP from the request headers
        otp = request.json.get('OTP')
        password = request.json.get('password')

        # Check if OTP was provided in the request
        if not otp:
            return message_response('Missing OTP', 400)

        # Retrieve the OTP stored in the session for verification
        session_otp = session.get('otp')
        session_email = session.get('email')

        if session_otp == otp:

            user = User.query.filter_by(email=session_email).first()
            if not password or len(password) < 7:
                return message_response('Password must be at least 7 characters long', 400)

            if check_password_hash(password, user.password):
                return message_response('This password is same as your last password.', 400)

            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            user.updated_at = db.func.now()
            user.is_active = False

            db.session.commit()
            session.clear()

            return message_response('Password reset successful!', 200)
    except Exception as e:
        logging.error(f"Error during reset: {e}")
        return message_response(str(e), 500)


@auth.route('/refresh_token')
@refresh_token_required
def refresh_token(current_user):
    try:
        # Generate a new JWT token
        token = generate_jwt_token(current_user)
        return message_response(
            'Token refreshed successfully.',
            200,
            Token=token
        )
    except Exception as e:
        logging.error(f"Error while refreshing token: {e}")
        return message_response(str(e), 500)
