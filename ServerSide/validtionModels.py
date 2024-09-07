from marshmallow import Schema, fields, validate


class SignupSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=7, max=20))
