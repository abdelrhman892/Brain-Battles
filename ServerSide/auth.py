from flask import Blueprint

auth = Blueprint('auth', __name__)


@auth.route('/log-in')
def login():
    pass


@auth.route('/log-out')
def logout():
    pass


@auth.route('/sign-up')
def register():
    pass
