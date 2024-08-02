from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from sqlalchemy.sql import func

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.Enum('Admin', 'User', name='user_roles'), nullable=False)
    created_date = db.Column(db.DateTime, default=func.now(), nullable=False)
    updated_date = db.Column(db.DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    active = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiration = db.Column(db.DateTime)


