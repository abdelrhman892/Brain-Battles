import logging
import uuid

import jwt
from flask import request, current_app, url_for
from flask_mail import Message

from . import view
from .. import mail, db
from ..helperFuncs import token_required, message_response
from ..models import Quiz, Answer, Score
from ..validtionModels import SendMailSchema
from marshmallow import ValidationError


@view.route('/send-quiz-link')
@token_required
def send_quiz_link(current_user):
    data = request.get_json()

    try:
        schema = SendMailSchema().load(data)
    except ValidationError as err:
        logging.error(err.messages)
        return message_response(err.messages, 400)

    quiz = Quiz.query.filter_by(id=schema.get('id')).first()
    if not quiz:
        return message_response('Quiz not found', 400)
    if quiz.visibility == 'public':
        return message_response('Quiz is public, this feature'
                                ' just for private quizzes', 200)

    access_token = jwt.encode({
        'id': schema.get('id'),
        'exp': quiz.expiration  # Token expires in 15 minutes
    }, current_app.config['SECRET_KEY'], algorithm='HS256')

    link = url_for('view.get_quiz_by_id', token=access_token, _external=True)
    try:
        # Send the link via email
        msg = Message('Brain-Battles: quiz invitation',
                      sender=current_app.config['MAIL_USERNAME'],
                      recipients=[schema.get('email')])
        msg.body = f'Click on the following link to access the quiz: {link}'

        mail.send(msg)
        return message_response("Access link sent!", 200)
    except Exception as e:
        logging.error(e)
        return message_response(str(e), 500)


@view.route('/submit_quiz')
@token_required
def submit_quiz(current_user):
    data = request.json
    quiz_id = data.get('quiz_id')
    answers = data.get('answers')  # This is expected to be a dict {question_id: selected_answer_id}

    if not quiz_id or not answers:
        return message_response("Quiz ID and answers are required", 400)

    # Fetch quiz
    quiz = Quiz.query.filter_by(id=quiz_id).first()
    if not quiz:
        return message_response("Quiz not found", 404)

    user_id = current_user.id

    # Initialize score calculation
    total_questions = len(quiz.questions)
    correct_answers = 0

    for question in quiz.questions:
        selected_answer_id = answers.get(str(question.id))

        if not selected_answer_id:
            continue  # Skip if no answer provided for this question

        # Fetch the correct answer for the question
        correct_answer = Answer.query.filter_by(question_id=question.id, is_correct=True).first()

        # Check if user's selected answer is correct
        if correct_answer and correct_answer.id == selected_answer_id:
            correct_answers += 1

    # Calculate score
    score_percentage = (correct_answers / total_questions) * 100 if total_questions > 0 else 0

    # Store the score
    score_entry = Score(
        id=str(uuid.uuid4()),
        user_id=user_id,
        quiz_id=quiz_id,
        score=score_percentage
    )
    db.session.add(score_entry)
    db.session.commit()

    # Return the score in response
    return message_response(
        "Score is calculated",
        200,
        quiz_id=quiz_id,
        user_id=user_id,
        score=score_percentage,
        correct_answers=correct_answers,
        total_questions=total_questions
    )
