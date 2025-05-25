from datetime import datetime
from flask_login import UserMixin
from .extensions import db
import secrets

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    google_id = db.Column(db.String(128), unique=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(32))
    api_key = db.Column(db.String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    files = db.relationship('File', backref='uploader', lazy=True)
    histories = db.relationship('History', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(32), nullable=False)
    encryption_method = db.Column(db.String(32))
    encryption_key = db.Column(db.String(128))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    permissions = db.relationship('Permission', backref='file', lazy=True, cascade="all, delete-orphan")

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    permission_type = db.Column(db.String(16), nullable=False)  # 'private', 'public', 'specific'
    specific_users = db.Column(db.String(256))  # comma-separated usernames

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    action = db.Column(db.String(16), nullable=False)  # 'upload', 'download', etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_hash = db.Column(db.String(64))
    filename = db.Column(db.String(256))
