from flask import Blueprint, request, session
from flask_mail import Message
from werkzeug.security import generate_password_hash
from . import db, mail
from .models import User
from .validtionModels import SignupSchema
from marshmallow.exceptions import ValidationError
from .helperFuncs import message_response, generate_otp

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

        # Generate a One Time Password (OTP) and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['email'] = email
        session['username'] = username
        session['password'] = generate_password_hash(password, method='pbkdf2:sha256')

        # Prepare and send an OTP email to the user
        msg = Message('Brain-Battles password assistance', sender='Brain-Battles', recipients=[email])
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


@auth.route('/log-in', methods=['GET', 'POST'])
def login():
    return "login page"


@auth.route('/log-out', methods=['GET', 'POST'])
def logout():
    return "logout page"
