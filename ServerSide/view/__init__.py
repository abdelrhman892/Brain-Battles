from flask import Blueprint

view = Blueprint('view', __name__)

from . import quiz
from . import question
