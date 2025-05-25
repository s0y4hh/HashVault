from app import db
from flask_login import UserMixin
from flask_bcrypt import generate_password_hash
import pyotp
import secrets

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    google_oauth_id = db.Column(db.String(128), unique=True, nullable=True)
    two_factor_secret = db.Column(db.String(16), nullable=True)
    api_key = db.Column(db.String(64), unique=True, nullable=False, default=lambda: secrets.token_hex(32))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return generate_password_hash(password).check_password_hash(self.password_hash)

    def generate_2fa_secret(self):
        self.two_factor_secret = pyotp.random_base32()

    def verify_2fa(self, token):
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token)

    def __repr__(self):
        return f'<User {self.username}>'
