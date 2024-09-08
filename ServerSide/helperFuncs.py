import logging
import random
import re
import string
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import jsonify, request, current_app

from ServerSide.models import User


# Helper function to format response messages for both success and error cases
def message_response(message, status_code, **kwargs):
    return jsonify({
        'message': message,
        'date': datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'),
        'status_code': status_code,
        **kwargs  # Unpack additional key-value pairs directly here
    }), status_code


# Function to generate a random OTP (One-Time Password) using digits
def generate_otp(length=6):
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(length))  # Generate OTP of specified length
    return otp


# Generates a short-lived JWT token for the user (expires in 7 minutes)
def generate_jwt_token(user):
    payload = {
        'user_id': user.id,  # User ID
        'email': user.email,  # User email
        'role': user.role,  # User role (e.g., admin, normal user)
        'is_active': user.is_active,  # user active
        'iat': datetime.now(timezone.utc),  # Issued at time
        'exp': datetime.now(timezone.utc) + timedelta(minutes=7),  # Expiration time (7 minutes)
        'jti': str(uuid.uuid4())  # Unique token identifier (JWT ID)
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    return token


# Generates a long-lived JWT token for the user (expires in 7 days)
def generate_long_token(user):
    payload = {
        'user_id': user.id,  # User ID
        'email': user.email,  # User email
        'role': user.role,  # User role (e.g., admin, normal user)
        'is_active': user.is_active,  # user active
        'iat': datetime.now(timezone.utc),  # Issued at time
        'exp': datetime.now(timezone.utc) + timedelta(days=7),  # Expiration time (7 days)
        'jti': str(uuid.uuid4())  # Unique token identifier (JWT ID)
    }
    token = jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token


# Decorator function to enforce token validation before accessing protected routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Get the token from the request headers
        if not token:
            # Return error if no token is provided
            return message_response('Token is missing', 404)

        try:
            # Decode the JWT token to extract user information
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            # Fetch user by email from the token
            current_user = User.query.filter_by(email=data['email']).first()

            # Validate if the token's data matches the user's current details
            if current_user is None:
                return message_response('Token is invalid', 401)  # Invalid token

            # Additional checks on role, email, and issued time
            if current_user.role != data['role'] or current_user.email != data['email'] \
                    or current_user.is_active != data['is_active']:
                return message_response('Invalid token', 401)

        # Handle token expiration and other exceptions
        except jwt.ExpiredSignatureError:
            return message_response('Token expired', 401)
        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid token: {e}")
            return message_response('Invalid token', 403)

        return f(current_user, *args, **kwargs)  # Pass the current user to the wrapped function

    return decorated


# Decorator for handling the refresh token validation in similar fashion to the `token_required` decorator
def refresh_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Get the token from the request headers
        if not token:
            # Return error if no token is provided
            return message_response('Token is missing', 404)

        try:
            # Decode the refresh JWT token
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            # Fetch user by email from the token
            current_user = User.query.filter_by(email=data['email']).first()

            # Validate if the token's data matches the user's current details
            if current_user is None:
                return message_response('Token is invalid', 401)  # Invalid token

            # Additional checks on role, email and active
            if current_user.role != data['role'] or current_user.email != data['email'] \
                    or current_user.is_active != data['is_active']:
                return message_response('Invalid token', 401)

        # Handle token expiration and other exceptions
        except jwt.ExpiredSignatureError:
            return message_response('Token expired', 401)
        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid token: {e}")
            return message_response('Invalid token', 403)

        return f(current_user, *args, **kwargs)  # Pass the current user to the wrapped function

    return decorated


email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'


def invalidate_email_format(email):
    if not re.match(email_regex, email):
        return True
    return False
