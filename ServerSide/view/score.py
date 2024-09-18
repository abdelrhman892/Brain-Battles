import logging

from flask import request

from . import view
from .. import db
from ..helperFuncs import token_required, message_response, invalid_email_format
from ..models import Quiz, Score, User
from ..validtionModels import ScoreSchema
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError


# Route to add a score for a user to a specific quiz
@view.route('/add_score', methods=['POST'])
@token_required  # Decorator to validate the user's JWT token
def add_score(current_user):
    try:
        # Parse the incoming JSON data
        data = request.get_json()
        if not data:  # If no data is received, return an error
            logging.error('No data')
            return message_response('missing data', 404)

        # Validate the data against the Score schema
        score_schema = ScoreSchema().load(data)

    except ValidationError as e:
        # Handle schema validation errors and return a bad request
        logging.error(e.messages)
        return message_response(e.messages, 400)

    # Retrieve the quiz ID from the request headers
    quiz_id = request.headers.get('X-Quiz-ID')
    if not quiz_id:  # If no quiz ID is provided, return an error
        logging.error('missing quiz_id')
        return message_response('Missing quiz ID', 400)

    try:
        # Ensure that the quiz exists in the database
        quiz = Quiz.query.filter_by(id=quiz_id).first()
        if not quiz:  # If the quiz is not found, return a not found error
            logging.error('Quiz not found')
            return message_response('Quiz not found', 404)

        # Create a new score record for the user and quiz
        score = Score(
            user_id=current_user.id,  # The current user's ID
            quiz_id=quiz_id,  # The quiz ID from the header
            score=score_schema.get('score')  # The score value from the request
        )

        # Add the new score record to the database
        db.session.add(score)
        db.session.commit()

        # Return a success message when the score is added successfully
        return message_response('Score added successfully', 201, score=score.to_dict())

    except SQLAlchemyError as e:
        # Handle any database errors and rollback the transaction
        logging.error(f"Database Error: {str(e)}")
        db.session.rollback()
        return message_response('Internal server error', 500)


@view.route('/get_scores', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_scores_by_user_email(current_user):
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
        user = current_user  # If not admin or no email header, use the current user's questions

    # Fetch all scores associated with the selected user (either the admin's queried user or the current user)
    scores = Score.query.filter_by(user_id=user.id).all()
    if not scores:  # If no scores are found for the user
        return message_response('No scores found', 404)

    # Return a success message along with the list of scores, serialized to dictionaries
    return message_response('scores fetched successfully',
                            200, scores=[score.to_dict() for score in scores])


@view.route('/get_score', methods=['GET'])
@token_required
def get_score_by_id(current_user):
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

    score_id = request.headers.get('X-Score-ID')
    if not score_id:
        return message_response('Missing score id', 400)

    # Retrieve the score for the current user and given user_id score_id from the header
    score = Score.query.filter_by(user_id=user.id, id=score_id).first()

    # Check if the score exists
    if not score:
        return message_response('Score not found', 404)

    # Respond with the score details and current date/time
    return message_response(
        'Successfully retrieved the score.',
        200,
        score=score.to_dict()
    )


@view.route('/scores', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_scores(current_user):
    # Check if the current user has a role of 'user' or 'moderator', and deny access if they do
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 403)

    try:
        # Attempt to fetch all scores from the database
        scores = Score.query.all()
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors that occur during the query
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response('An error occurred while fetching scores', 500)

    # Check if no scores were found
    if not scores:
        return message_response('No scores found', 404)

    # Return a success message along with the list of all scores, serialized to dictionaries
    return message_response(
        'scores fetched successfully',
        200, scores=[score.to_dict() for score in scores])


@view.route('/delete_score', methods=['DELETE'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def delete_score(current_user):
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

    score_id = request.headers.get('X-Score-ID')  # Retrieve the 'X-Score_id' from the request arguments
    if not score_id:
        return message_response('Missing score id', 400)

    try:
        # Retrieve the score for the current user with the given 'question_id'
        score = Score.query.filter_by(user_id=user.id, id=score_id).first()
        if not score:  # If no score is found with the given 'score_id'
            return message_response('score not found', 404)

        db.session.delete(score)  # Delete the score from the session
        db.session.commit()  # Commit the session to apply the deletion
        return message_response('Successfully deleted the score.', 200)
    except SQLAlchemyError as e:  # Catch any SQLAlchemy-related errors during the delete operation
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response(str(e), 500)


@view.route('/update_score', methods=['PATCH'])
@token_required
def update_score(current_user):
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

    score_id = request.headers.get('X-Score-ID')  # Retrieve the score ID from the request headers
    if not score_id:
        return message_response('Missing score id', 400)

    score = Score.query.filter_by(user_id=user.id, id=score_id).first()
    if not score:  # If the score is not found
        return message_response('score not found', 404)

    data = request.get_json()  # Get JSON data from the request body
    if not data:
        return message_response('No data provided', 400)

    try:
        validated_data = ScoreSchema().load(data)
    except ValidationError as e:
        logging.error(e)
        return message_response(str(e), 400)

    score.score = data['score']
    try:
        score.updated_at = db.func.now()  # Update the 'updated_at' timestamp
        db.session.commit()  # Commit the transaction to save changes

        return message_response('score updated successfully.',
                                200, updated_fields=validated_data)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(e)
        message_response(str(e), 400)
