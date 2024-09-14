import uuid
from datetime import datetime, timezone, timedelta

from . import db

role = {
    'ADMIN': 'admin',
    'MODERATOR': 'moderator',
    'USER': 'user'
}


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(),
                           onupdate=db.func.now(), nullable=False)
    role = db.Column(db.String, default=role.get('USER'))
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)

    quizzes = db.relationship('Quiz', backref='author', lazy='joined')
    questions = db.relationship('Question', backref='author', lazy='joined')
    answers = db.relationship('Answer', backref='author', lazy='joined')
    scores = db.relationship('Score', backref='user', lazy='joined')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'email_verified': self.email_verified,
            'role': self.role,
            'quizzes': [quiz.to_dict() for quiz in self.quizzes],
            'scores': [score.to_dict() for score in self.scores]
        }


class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    visibility = db.Column(db.String, nullable=False, default='public')
    last_editable_at = db.Column(db.DateTime, nullable=False,
                                 default=lambda: datetime.now() + timedelta(days=2))
    expiration = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now() + timedelta(days=1))
    timer = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(),
                           onupdate=db.func.now(), nullable=False)

    questions = db.relationship('Question', backref='quiz', lazy='joined', cascade="all, delete-orphan")
    scores = db.relationship('Score', backref='quiz', lazy='joined', cascade="all, delete-orphan")

    def to_dict(self):
        def format_datetime(dt):
            return dt.strftime('%Y-%m-%d %I:%M:%S %p') if dt else None

        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'last_editable_at': format_datetime(self.last_editable_at),
            'expiration': format_datetime(self.expiration),
            'timer': self.timer,
            'user_id': self.user_id,
            'created_at': format_datetime(self.created_at),
            'updated_at': format_datetime(self.updated_at),
            'questions': [question.to_dict() for question in self.questions],
            'scores': [score.to_dict() for score in self.scores],
        }


class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    question_text = db.Column(db.String, nullable=False)
    quiz_id = db.Column(db.String, db.ForeignKey('quizzes.id'), nullable=False, index=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(),
                           onupdate=db.func.now(), nullable=False)

    answers = db.relationship('Answer', backref='question', lazy='joined')

    def to_dict(self):
        return {
            'id': self.id,
            'question_text': self.question_text,
            'quiz_id': self.quiz_id,
            'user_id': self.user_id,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'answers': [answer.to_dict() for answer in self.answers],
        }


class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    answer_text = db.Column(db.String, nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, index=True)
    quiz_id = db.Column(db.String, db.ForeignKey('quizzes.id'), nullable=False, index=True)
    question_id = db.Column(db.String, db.ForeignKey('questions.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(),
                           onupdate=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'answer_text': self.answer_text,
            'quiz_id': self.quiz_id,
            'user_id': self.user_id,
            'question_id': self.question_id,
            'created_at': self.created_at,
            'is_correct': self.is_correct,
        }


class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, index=True)
    quiz_id = db.Column(db.String, db.ForeignKey('quizzes.id'), nullable=False, index=True)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(),
                           onupdate=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'quiz_id': self.quiz_id,
            'score': self.score,
        }
