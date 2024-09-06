import logging
import random
import string
from datetime import datetime
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


# Decorator function to enforce token validation before accessing protected routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.authorization.split(' ')[1]  # Get the token from the request headers
        # token = request.headers.get('Authorization')
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
                    or current_user.is_active != data['active']:
                return message_response('Invalid token', 401)

        # Handle token expiration and other exceptions
        except jwt.ExpiredSignatureError:
            return message_response('Token expired', 401)
        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid token: {e}")
            return message_response('Invalid token', 403)

        return f(current_user, *args, **kwargs)  # Pass the current user to the wrapped function

    return decorated
