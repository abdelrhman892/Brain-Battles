import logging

from flask import request
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from .. import db
from ..helperFuncs import token_required, message_response, invalid_email_format
from . import view
from ..models import Quiz, Question, Answer, User
from ..validtionModels import AnswerSchema


@view.route('/add_answer', methods=['POST'])
@token_required
def add_answer(current_user):
    try:
        data = request.get_json()  # Get JSON data from the request body
        if not data:
            return message_response('Missing data', 400)

        # Validate and deserialize the input data using AnswerSchema
        answer_schema = AnswerSchema().load(data)
    except ValidationError as err:
        # Log validation errors with specific details
        logging.error(f"Validation error: {err.messages}")
        return message_response(err.messages, 400)

    # Retrieve the quiz ID from the request headers
    quiz_id = request.headers.get('X-Quiz-ID')
    if not quiz_id:
        return message_response('Missing quiz ID', 400)
    question_id = request.headers.get('X-Question-ID')
    if not question_id:
        return message_response('Missing question ID', 400)

    try:
        # Ensure the quiz exists
        # Query the Quiz table to find the quiz with the given ID
        quiz = Quiz.query.filter_by(id=quiz_id).first()
        if not quiz:  # If the quiz is not found
            return message_response('Quiz not found', 404)

        # Ensure the question exists
        # Query the Question table to find the quiz with the given ID
        question = Question.query.filter_by(id=question_id).first()
        if not question:  # If the quiz is not found
            return message_response('Question not found', 404)

        # Create a new answer object with the validated data
        #       and associate it with the quiz, question and current user
        new_answer = Answer(
            answer_text=answer_schema['answer_text'],
            is_correct=answer_schema['is_correct'],
            user_id=current_user.id,
            quiz_id=quiz.id,
            question_id=question.id
        )

        db.session.add(new_answer)  # Add the new answer to the database session
        db.session.commit()  # Commit the transaction to save changes

        # Return a success response with the newly created answer data
        return message_response('Answer created successfully',
                                201,  # HTTP status code for created resource
                                answer=new_answer.to_dict())
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors during the operation
        logging.error(f"Database error while adding question: {e}")  # Log the error with specific details
        db.session.rollback()  # Rollback the session to maintain data integrity
        return message_response('An error occurred while adding the question.',
                                500)


@view.route('/get_answers', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_answers_by_user_email(current_user):
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

    # Fetch all answers associated with the selected user (either the admin's queried user or the current user)
    answers = Answer.query.filter_by(user_id=user.id).all()
    if not answers:  # If no answers are found for the user
        return message_response('No answers found', 404)

    # Return a success message along with the list of answers, serialized to dictionaries
    return message_response('answers fetched successfully',
                            200, quizzes=[answer.to_dict() for answer in answers])


@view.route('/get_answer', methods=['GET'])
@token_required
def get_answer_by_id(current_user):
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

    answer_id = request.headers.get('X-Answer-ID')
    if not answer_id:
        return message_response('Missing answer id', 400)

    # Retrieve the answer for the current user and given user_id answer_id from the header
    answer = Answer.query.filter_by(user_id=user.id, id=answer_id).first()

    # Check if the answer exists
    if not answer:
        return message_response('answer not found', 404)

    # Respond with the answer details and current date/time
    return message_response(
        'Successfully retrieved the answer.',
        200,
        answer=answer.to_dict()
    )


@view.route('/answers', methods=['GET'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def get_all_answers(current_user):
    # Check if the current user has a role of 'user' or 'moderator', and deny access if they do
    if current_user.role in ['user', 'moderator']:
        return message_response('Access denied', 403)

    try:
        # Attempt to fetch all answers from the database
        answers = Answer.query.all()
    except SQLAlchemyError as e:  # Catch any SQLAlchemy errors that occur during the query
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response('An error occurred while fetching answers', 500)

    # Check if no answers were found
    if not answers:
        return message_response('No answers found', 404)

    # Return a success message along with the list of all answers, serialized to dictionaries
    return message_response(
        'answers fetched successfully',
        200, answer=[answer.to_dict() for answer in answers])


@view.route('/delete_answer', methods=['DELETE'])
@token_required  # Ensures the user is authenticated using a token before accessing the route
def delete_answer(current_user):
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

    answer_id = request.headers.get('X-Answer-ID')  # Retrieve the 'X-Answer_id' from the request arguments
    if not answer_id:
        return message_response('Missing answer id', 400)

    try:
        # Retrieve the answer for the current user with the given 'answer_id'
        answer = Answer.query.filter_by(user_id=user.id, id=answer_id).first()
        if not answer:  # If no answer is found with the given 'answer_id'
            return message_response('question not found', 404)

        db.session.delete(answer)  # Delete the answer from the session
        db.session.commit()  # Commit the session to apply the deletion
        return message_response('Successfully deleted the answer.', 200)
    except SQLAlchemyError as e:  # Catch any SQLAlchemy-related errors during the delete operation
        db.session.rollback()  # Rollback the session to maintain data integrity
        logging.error(e)  # Log the error for debugging purposes
        return message_response(str(e), 500)


@view.route('/update_answer', methods=['PATCH'])
@token_required
def update_answer(current_user):
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

    answer_id = request.headers.get('X-Answer-ID')  # Retrieve the answer ID from the request headers
    if not answer_id:
        return message_response('Missing answer id', 400)

    answer = Answer.query.filter_by(user_id=user.id, id=answer_id).first()
    if not answer:  # If the answer is not found
        return message_response('answer not found', 404)

    data = request.get_json()  # Get JSON data from the request body
    if not data:
        return message_response('No data provided', 400)

    try:
        validated_data = AnswerSchema().load(data, partial=True)
    except ValidationError as e:
        logging.error(e)
        return message_response(str(e), 400)

    # Update the answer fields with the validated data
    for field, value in validated_data.items():
        setattr(answer, field, value)

    try:
        answer.updated_at = db.func.now()  # Update the 'updated_at' timestamp
        db.session.commit()  # Commit the transaction to save changes

        return message_response('answer updated successfully.',
                                200, updated_fields=validated_data)

    except SQLAlchemyError as e:
        logging.error(f"Error while updating answer: {e}")  # Log the error for debugging purposes
        db.session.rollback()  # Rollback the session to maintain data integrity
        return message_response('An error occurred while updating the answer.', 500)
