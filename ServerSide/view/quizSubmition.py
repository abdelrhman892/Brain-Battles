import logging
from datetime import datetime, timedelta

import jwt
from flask import request, current_app, url_for
from flask_mail import Message

from . import view
from .. import mail
from ..helperFuncs import token_required, message_response
from ..models import Quiz
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
