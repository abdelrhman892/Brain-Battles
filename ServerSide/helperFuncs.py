import logging
import random
import re
import string
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import jsonify, request, current_app
from marshmallow import ValidationError

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


def invalid_email_format(email):
    if not re.match(email_regex, email):
        return True
    return False


def parse_duration(duration_str):
    """Parse a human-readable duration string into a timedelta object."""
    # Patterns to match duration formats
    patterns = {
        'days': re.compile(r'(\d+)\s*day', re.IGNORECASE),
        'hours': re.compile(r'(\d+)\s*hour', re.IGNORECASE),
        'minutes': re.compile(r'(\d+)\s*minute', re.IGNORECASE),
    }

    duration = timedelta()
    for unit, pattern in patterns.items():
        match = pattern.search(duration_str)
        if match:
            value = int(match.group(1))
            if unit == 'days':
                duration += timedelta(days=value)
            elif unit == 'hours':
                duration += timedelta(hours=value)
            elif unit == 'minutes':
                duration += timedelta(minutes=value)

    return duration


# Custom validator function to handle singular/plural time units
def validate_time_duration(value):
    # Regular expression for matching patterns like "1 day", "2 days", "1 hour", "30 minutes"
    pattern = re.compile(r"^(\d+)\s*(day|days|hour|hours|minute|minutes)$")
    match = pattern.match(value)

    if not match:
        raise ValidationError("Invalid time format. Valid formats: e.g.,"
                              " '1 day', '2 days', '12 hours', '30 minutes'.")

    # Extract the number and time unit from the match
    number = int(match.group(1))
    unit = match.group(2)

    # Validate that the singular/plural form is correct based on the number
    if number == 1 and unit not in ["day", "hour", "minute"]:
        raise ValidationError(f"For '1', the correct form is singular"
                              f" (e.g., '1 day', '1 hour', '1 minute').")
    if number > 1 and unit not in ["days", "hours", "minutes"]:
        raise ValidationError(
            f"For numbers greater than '1', the correct form is plural "
            f"(e.g., '2 days', '3 hours', '10 minutes').")
