import logging
from datetime import datetime

import jwt
from flask import request, current_app
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from . import view
from .. import db
from ..helperFuncs import token_required, message_response, invalid_email_format, parse_duration
from ..models import Quiz, User
from ..validtionModels import QuizSchema


@view.route('/add_quiz', methods=['POST'])
@token_required  # Ensure the user is authenticated with a valid token before accessing this route
def add_quiz(current_user):
    try:
        data = request.get_json()
        if not data:
            return message_response('Missing data', 404)
        # Attempt to validate and deserialize the incoming JSON request using QuizSchema
        quizSchema = QuizSchema().load(data)
    except ValidationError as err:
        # Log validation errors and return an appropriate error response with the error messages
        logging.error(err.messages)
        return message_response(err.messages, 401)

    # Create a new Quiz object using the validated data and associate it with the current user
    now = datetime.now()
    new_quiz = Quiz(
        title=quizSchema['title'],
        description=quizSchema['description'],
        visibility=quizSchema['visibility'],
        last_editable_at=now + parse_duration(quizSchema['last_editable_at']),
        # Expiration will start after last_editable_at end cuz he
        #       cannot edit the quiz after the quiz is taking
        expiration=now + (parse_duration(quizSchema['last_editable_at'])
                          + parse_duration(quizSchema['expiration'])),
        timer=parse_duration(quizSchema['timer']).total_seconds(),
        user_id=current_user.id
    )
    try:
        # Add the new quiz to the database session and attempt to commit the changes
        db.session.add(new_quiz)
        db.session.commit()

        # Return a success response with the newly created quiz details
        return message_response('Quiz successfully added', 201, quiz=new_quiz.to_dict())
    except SQLAlchemyError as e:
        # Roll back the transaction if there's a database error, log the error, and return an appropriate response
        db.session.rollback()
        logging.error(e)
        return message_response(str(e), 500)


@view.route('/get_quizzes', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_quiz_by_user_email(current_user):
    # Check if the current user is an admin and an 'Email' header is provided in the request
    if current_user.role == 'admin' and request.headers.get('Email'):
        # Retrieve the 'Email' header from the request
        email = request.headers.get('Email')
        # Validate if the email is provided and has the correct format
        if not email or invalid_email_format(email):
            return message_response('Invalid email format', 400)

        # Query the User table to find a user with the provided email
        user = User.query.filter_by(email=email).first()
        if not user:  # If no user is found with the provided email
            return message_response('User does not exist', 404)
    else:
        user = current_user  # If not admin or no email header, use the current user's quizzes

    # Fetch all quizzes associated with the selected user (either the admin's queried user or the current user)
    quizzes = Quiz.query.filter_by(user_id=user.id).all()
    if not quizzes:  # If no quizzes are found for the user
        return message_response('No quizzes found', 404)

    # Return a success message along with the list of quizzes, serialized to dictionaries
    return message_response('Quizzes fetched successfully',
                            200, quizzes=[quiz.to_dict() for quiz in quizzes])


@view.route('/get_quiz', methods=['GET'])
@token_required
def get_quiz_by_id(current_user):
    # Check if the current user is an admin and an 'Email' header is provided in the request
    if current_user.role == 'admin' and request.headers.get('Email'):
        # Retrieve the 'Email' header from the request
        email = request.headers.get('Email')
        # Validate if the email is provided and has the correct format
        if not email or invalid_email_format(email):
            return message_response('Invalid email format', 400)

        # Query the User table to find a user with the provided email
        user = User.query.filter_by(email=email).first()
        if not user:  # If no user is found with the provided email
            return message_response('User does not exist', 404)
    else:
        user = current_user  # If not admin or no email header, use the current user's quizzes

    # Check if 'X-Quiz-ID' is present in the request headers
    if request.headers.get('X-Quiz-ID'):
        quiz_id = request.headers.get('X-Quiz-ID')
        # Retrieve the quiz for the current user using the 'quiz_id' from the header
        quiz = Quiz.query.filter_by(user_id=user.id, id=quiz_id).first()
    else:
        try:
            # Retrieve the 'token' from the query parameters
            token = request.args.get('token')
            # Validate that 'token' is present
            if not token:
                return message_response('Missing token or quiz_id', 400)
            # Decode the token to get the payload data
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            # Handle the case where the token has expired
            return message_response('The quiz is no longer available because'
                                    ' the time limit has passed.', 401)
        except jwt.InvalidTokenError:
            # Handle the case where the token is invalid
            return message_response('The token is invalid', 401)
        # Extract 'quiz_id' from the token payload
        quiz_id = data.get('id')

        if not quiz_id:
            return message_response('Missing quiz id', 400)
        # Retrieve the quiz for the current user and given quiz_id from the header
        quiz = Quiz.query.filter_by(id=quiz_id).first()

    # Check if the quiz exists
    if not quiz:
        return message_response('Quiz not found', 404)

    # Respond with the quiz details and current date/time
    return message_response(
        'Successfully retrieved the quiz.',
        200,
        quiz=quiz.to_dict()
    )


@view.route('/quizzes', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_quizzes(current_user):
    # Check if the current user has a role of 'user' or 'moderator', and deny access if they do
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 403)

    try:
        # Attempt to fetch all quizzes from the database
        quizzes = Quiz.query.all()
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors that occur during the query
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response('An error occurred while fetching quizzes', 500)

    # Check if no quizzes were found
    if not quizzes:
        return message_response('No quizzes found', 404)

    # Return a success message along with the list of all quizzes, serialized to dictionaries
    return message_response(
        'Quizzes fetched successfully',
        200, quizzes=[quiz.to_dict() for quiz in quizzes])


@view.route('/delete_quiz', methods=['DELETE'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def delete_quiz(current_user):
    # Check if the current user is an admin and an 'Email' header is provided in the request
    if current_user.role == 'admin' and request.headers.get('Email'):
        email = request.headers.get('Email')  # Retrieve the 'Email' header from the request
        # Validate if the email is provided and has the correct format
        if not email or invalid_email_format(email):
            return message_response('Invalid email format', 400)

        # Query the User table to find a user with the provided email
        user = User.query.filter_by(email=email).first()
        if not user:  # If no user is found with the provided email
            return message_response('User does not exist', 404)
    else:
        user = current_user  # If not admin or no email header, use the current user's details

    quiz_id = request.headers.get('X-Quiz-ID')  # Retrieve the 'quiz_id' from the request arguments
    if not quiz_id:
        return message_response('Missing quiz id', 400)

    try:
        # Retrieve the quiz for the current user with the given 'quiz_id'
        quiz = Quiz.query.filter_by(user_id=user.id, id=quiz_id).first()
        if not quiz:  # If no quiz is found with the given 'quiz_id'
            return message_response('Quiz not found', 404)

        db.session.delete(quiz)  # Delete the quiz from the session
        db.session.commit()  # Commit the session to apply the deletion
        return message_response('Successfully deleted the quiz.', 200)
    except SQLAlchemyError as e:  # Catch any SQLAlchemy-related errors during the delete operation
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response(str(e), 500)


@view.route('/update_quiz', methods=['PATCH'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def update_quiz(current_user):
    # Check if the current user is an admin and an 'Email' header is provided in the request
    if current_user.role == 'admin' and request.headers.get('Email'):
        # Retrieve and strip the 'Email' header from the request
        email = request.headers.get('Email', '').strip()
        # Validate if the email is provided and has the correct format
        if not email or invalid_email_format(email):
            return message_response('Invalid email format', 400)

        # Query the User table to find a user with the provided email
        user = User.query.filter_by(email=email).first()
        if not user:  # If no user is found with the provided email
            return message_response('User does not exist', 404)
    else:
        user = current_user  # If not admin or no email header, use the current user's context

    quiz_id = request.headers.get('X-Quiz-ID')  # Retrieve the quiz ID from the request headers
    if not quiz_id:
        return message_response('Missing quiz id', 400)

    quiz = Quiz.query.filter_by(user_id=user.id, id=quiz_id).first()
    if not quiz:  # If the quiz is not found
        return message_response('Quiz not found', 404)

    if datetime.now() >= quiz.last_editable_at:  # check if the author can update more
        return message_response('You can no longer edit this quiz,'
                                ' the editing period has ended', 400)

    data = request.get_json()  # Get JSON data from the request body
    if not data:
        return message_response('No data provided', 400)

    schema = QuizSchema()  # Create an instance of the QuizSchema for validation
    try:
        # Validate and deserialize the input data; 'partial=True' allows for partial updates
        validated_data = schema.load(data, partial=True)
    except ValidationError as err:
        logging.error(err.messages)  # Log validation errors
        return message_response(err.messages, 400)

    # Update the quiz fields with the validated data
    for field, value in validated_data.items():
        setattr(quiz, field, value)

    try:
        quiz.updated_at = db.func.now()  # Update the 'updated_at' timestamp
        db.session.commit()  # Commit the transaction to save changes

        return message_response('Quiz updated successfully.',
                                200, updated_fields=validated_data)

    except SQLAlchemyError as e:
        logging.error(f"Error while updating quiz: {e}")  # Log the error for debugging purposes
        db.session.rollback()  # Rollback the session to maintain data integrity
        return message_response('An error occurred while updating the quiz.', 500)
