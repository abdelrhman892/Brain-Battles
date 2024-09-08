import logging

from flask import Blueprint, request
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

from .. import db
from ..helperFuncs import token_required, message_response, invalidate_email_format
from ..models import User
from ..validtionModels import SignupSchema

user = Blueprint('user', __name__)


@user.route('/add_user', methods=['POST'])
@token_required
def add_user(current_user):
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 401)

    schema = SignupSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        logging.error(err.messages)
        return message_response(err.messages, 403)

    is_user = User.query.filter_by(email=data['email']).first()
    if is_user:
        return message_response('User already exists', 409)

    try:
        new_user = User(
            username=data['username'],
            email=data['email'],
            password=generate_password_hash(password=data['password'], method='pbkdf2:sha256'),
        )
        db.session.add(new_user)
        db.session.commit()
        return message_response('User created successfully', 201)
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        return message_response(str(e), 500)


@user.route('/get_users', methods=['GET'])
@token_required
def get_users(current_user):
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 401)

    try:
        users = User.query.all()
        return message_response(
            'Successfully fetched all users.',
            200,
            users=[u.to_dict() for u in users]
        )
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        return message_response(str(e), 500)


@user.route('/get_user', methods=['GET'])
@token_required
def get_user_by_email(current_user):
    email = request.headers.get('Email') if current_user.role == 'admin' else current_user.email

    if not email or invalidate_email_format(email):
        return message_response('Invalid email format', 401)

    try:
        is_user = User.query.filter_by(email=email).first()
        if is_user:
            return message_response('user found successfully.',
                                    200,
                                    user=is_user.to_dict())
        else:
            return message_response('User does not exist', 404)
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        return message_response(str(e), 500)


@user.route('/update_user', methods=['PATCH'])
@token_required
def update_user(current_user):
    email = request.headers.get('Email') if (
                current_user.role == 'admin' and request.headers.get('Email')) else current_user.email

    if not email or invalidate_email_format(email):
        return message_response('Invalid email format', 401)

    is_user = User.query.filter_by(email=email).first()
    if not is_user:
        return message_response('User not found.', 404)

    value = request.get_json()  # Get the updated data from the request
    if not value:
        return message_response('No data provided for update.', 400)

    updated_fields = {}

    # Update password if provided and valid
    if 'password' in value:
        new_password = value['password']
        if len(new_password) < 7:
            return message_response('Password must be at least 7 characters.', 400)

        if not check_password_hash(is_user.password, new_password):
            return message_response('This password is the same as your old password.', 400)

        is_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        is_user.is_active = False
        updated_fields['password'] = 'Updated'

    # Update username if provided and valid
    if 'username' in value:
        new_username = value['username']
        if len(new_username) < 3:
            return message_response('Username must be at least 3 characters.', 400)

        # Ensure the new username isn't already in use by another user
        if User.query.filter_by(username=new_username).first() and new_username != is_user.username:
            return message_response('Username already in use.', 400)

        if is_user.username == value['username']:
            return message_response('This username is same as your last username.', 400)

        is_user.username = new_username
        updated_fields['username'] = new_username

    if 'role' in value:
        if value['role'] in ['admin', 'moderator', 'user']:
            is_user.role = value['role']
            updated_fields['role'] = value['role']
        else:
            return message_response('Invalid role provided.', 400)

    if not updated_fields:
        return message_response('No valid fields were provided for update.', 400)

    try:
        # Commit the updated data to the database
        is_user.updated_at = db.func.now()
        db.session.commit()

        return message_response(
            'User updated successfully.',
            200,
            updated_fields=updated_fields,
        )
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        return message_response(str(e), 500)


@user.route('/delete_user', methods=['DELETE'])
@token_required
def delete_user(current_user):
    if not current_user.role == 'admin':
        return message_response('Access denied', 401)

    email = request.headers.get('email')
    if not email or invalidate_email_format(email):
        return message_response('Invalid email format', 401)
    try:
        is_user = User.query.filter_by(email=email).first()
        if is_user:
            db.session.delete(is_user)
            db.session.commit()
            return message_response('User deleted successfully.', 200)
        else:
            return message_response('User does not exist.', 404)
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        return message_response(str(e), 500)