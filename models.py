from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# User model for authentication
class User(db.Model):
    __tablename__ = 'user'  # Explicitly define the table name
    __table_args__ = {'extend_existing': True}  # Allow redefining the table

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


# Password model for storing passwords
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<Password {self.id}>'

# InputControl model for allowing/disabling form inputs
class InputControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accepting_inputs = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"InputControl(accepting_inputs={self.accepting_inputs})"
