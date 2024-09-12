from marshmallow import Schema, fields, validate
from .helperFuncs import validate_time_duration


class SignupSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))


class UpdateUserSchema(Schema):
    username = fields.Str(
        validate=[
            validate.Length(min=3, error='Username must be at least 3 characters.')
        ]
    )
    password = fields.Str(
        validate=[
            validate.Length(min=7, error='Password must be at least 7 characters.')
        ]
    )
    role = fields.Str(
        validate=[
            validate.OneOf(['admin', 'moderator', 'user'], error='Invalid role provided.')
        ]
    )


class QuizSchema(Schema):
    title = fields.Str(
        required=True,
        validate=[
            validate.Length(min=5, error='Title is too short'),
        ]
    )
    description = fields.Str(
        required=True,
        validate=[
            validate.Length(min=10, error='Description is too short'),
            validate.Regexp(r'^[A-Za-z0-9 ,.!?]+$',
                            error='Description can only contain alphanumeric characters, spaces, and basic punctuation')
        ]
    )

    last_editable_at = fields.Str(
        required=True,
        validate=validate_time_duration
    )

    expiration = fields.Str(
        required=True,
        validate=validate_time_duration
    )

    timer = fields.Str(
        required=True,
        validate=validate_time_duration
    )


class QuestionSchema(Schema):
    question_text = fields.Str(
        required=True,
        validate=[
            validate.Length(min=5, error='question text is too short'),
        ]
    )


class AnswerSchema(Schema):
    answer_text = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, error='Answer text is too short'),
        ]
    )
    is_correct = fields.Bool(required=True)


class ScoreSchema(Schema):
    score = fields.Float(required=True)


class SendMailSchema(Schema):
    email = fields.Email(required=True)
    id = fields.UUID(required=True)
