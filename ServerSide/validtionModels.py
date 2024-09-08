from marshmallow import Schema, fields, validate


class SignupSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))


class QuizSchema(Schema):
    title = fields.Str(
        required=True,
        validate=[
            validate.Length(min=5, error='Title is too short'),
            validate.Regexp(r'^[A-Za-z0-9 ]+$', error='Title can only contain alphanumeric characters and spaces')
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
