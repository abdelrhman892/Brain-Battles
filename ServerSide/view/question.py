import logging

from flask import request

from .. import db
from ..helperFuncs import token_required, message_response, invalid_email_format
from . import view
from ..models import Question, Quiz, User
from ..validtionModels import QuestionSchema
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError


@view.route('/add_question', methods=['POST'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def add_question(current_user):
    try:
        data = request.get_json()  # Get JSON data from the request body
        if not data:
            return message_response('Missing data', 400)

        # Validate and deserialize the input data using QuestionSchema
        question_schema = QuestionSchema().load(data)
    except ValidationError as err:
        # Log validation errors with specific details
        logging.error(f"Validation error: {err.messages}")
        return message_response(err.messages, 400)

    # Retrieve the quiz ID from the request headers
    quiz_id = request.headers.get('X-Quiz-ID')
    if not quiz_id:
        return message_response('Missing quiz ID', 400)

    try:
        # Ensure the quiz exists
        # Query the Quiz table to find the quiz with the given ID
        quiz = Quiz.query.filter_by(id=quiz_id).first()
        if not quiz:  # If the quiz is not found
            return message_response('Quiz not found', 404)

        # Create a new Question object with the validated data
        #       and associate it with the quiz and current user
        new_question = Question(
            question_text=question_schema['question_text'],
            user_id=current_user.id,
            quiz_id=quiz.id
        )

        db.session.add(new_question)  # Add the new question to the database session
        db.session.commit()  # Commit the transaction to save changes

        # Return a success response with the newly created question data
        return message_response('Question created successfully',
                                201,  # HTTP status code for created resource
                                question=new_question.to_dict())
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors during the operation
        logging.error(f"Database error while adding question: {e}")  # Log the error with specific details
        db.session.rollback()  # Rollback the session to maintain data integrity
        return message_response('An error occurred while adding the question.',
                                500)


@view.route('/get_questions', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_questions_by_user_email(current_user):
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

    # Fetch all questions associated with the selected user (either the admin's queried user or the current user)
    questions = Question.query.filter_by(user_id=user.id).all()
    if not questions:  # If no questions are found for the user
        return message_response('No questions found', 404)

    # Return a success message along with the list of questions, serialized to dictionaries
    return message_response('questions fetched successfully',
                            200, quizzes=[question.to_dict() for question in questions])


@view.route('/get_question', methods=['GET'])
@token_required
def get_question_by_id(current_user):
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

    question_id = request.headers.get('X-Question-ID')
    if not question_id:
        return message_response('Missing question id', 400)

    # Retrieve the question for the current user and given user_id question_id from the header
    question = Question.query.filter_by(user_id=user.id, id=question_id).first()

    # Check if the question exists
    if not question:
        return message_response('Question not found', 404)

    # Respond with the question details and current date/time
    return message_response(
        'Successfully retrieved the question.',
        200,
        question=question.to_dict()
    )


@view.route('/questions', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_questions(current_user):
    # Check if the current user has a role of 'user' or 'moderator', and deny access if they do
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 403)

    try:
        # Attempt to fetch all questions from the database
        questions = Question.query.all()
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors that occur during the query
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response('An error occurred while fetching questions', 500)

    # Check if no questions were found
    if not questions:
        return message_response('No questions found', 404)

    # Return a success message along with the list of all questions, serialized to dictionaries
    return message_response(
        'questions fetched successfully',
        200, questions=[question.to_dict() for question in questions])


@view.route('/delete_question', methods=['DELETE'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def delete_question(current_user):
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

    question_id = request.headers.get('X-Question-ID')  # Retrieve the 'X-Question_id' from the request arguments
    if not question_id:
        return message_response('Missing question id', 400)

    try:
        # Retrieve the question for the current user with the given 'question_id'
        question = Question.query.filter_by(user_id=user.id, id=question_id).first()
        if not question:  # If no question is found with the given 'question_id'
            return message_response('question not found', 404)

        db.session.delete(question)  # Delete the question from the session
        db.session.commit()  # Commit the session to apply the deletion
        return message_response('Successfully deleted the question.', 200)
    except SQLAlchemyError as e:  # Catch any SQLAlchemy-related errors during the delete operation
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response(str(e), 500)


@view.route('/update_question', methods=['PATCH'])
@token_required
def update_question(current_user):
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

    question_id = request.headers.get('X-Quiz-ID')  # Retrieve the question ID from the request headers
    if not question_id:
        return message_response('Missing question id', 400)

    question = Question.query.filter_by(user_id=user.id, id=question_id).first()
    if not question:  # If the question is not found
        return message_response('question not found', 404)

    data = request.get_json()  # Get JSON data from the request body
    if not data:
        return message_response('No data provided', 400)

    try:
        validated_data = QuestionSchema().load(data)
    except ValidationError as e:
        logging.error(e)
        return message_response(str(e), 400)

    question.question_text = data['question_text']
    try:
        question.updated_at = db.func.now()  # Update the 'updated_at' timestamp
        db.session.commit()  # Commit the transaction to save changes

        return message_response('question updated successfully.',
                                200, updated_fields=validated_data)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(e)
        message_response(str(e), 400)
