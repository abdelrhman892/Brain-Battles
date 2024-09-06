from flask import Blueprint, request
from werkzeug.security import generate_password_hash
from . import db
from .models import User
from .validtionModels import SignupSchema
from marshmallow.exceptions import ValidationError
from .helperFuncs import message_response


auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['POST'])
def register():
    try:
        # Initialize the schema for validating sign-up data
        schema = SignupSchema()

        try:
            # Load and validate incoming JSON data using the schema
            data = schema.load(request.json)
        except ValidationError as err:
            # Return validation errors with a 400 Bad Request status
            return message_response(err.messages, 400)

        username = data['username']
        email = data['email']

        # Check if the email is already registered in the database
        if User.query.filter_by(email=email).first():
            # Return an error message if the email is already in use
            return message_response('Email already registered', 409)

        # Create a new User instance with the provided data and hashed password
        user = User(username=username,
                    email=email,
                    password=generate_password_hash(data['password'], method='scrypt'))

        # Add the new user to the session and commit to the database
        db.session.add(user)
        db.session.commit()

        # Return a success message with a 200 OK status
        return message_response('Account created successfully!', 200)
    except Exception as e:
        # Return a generic error message with a 500 Internal Server Error status
        return message_response(str(e), 500)


@auth.route('/log-in', methods=['GET', 'POST'])
def login():
    return "login page"


@auth.route('/log-out', methods=['GET', 'POST'])
def logout():
    return "logout page"
