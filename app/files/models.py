from app import db
from sqlalchemy.sql import func

class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encryption_algorithm = db.Column(db.String(50), nullable=True)
    encryption_key = db.Column(db.String(128), nullable=True)
    permissions = db.Column(db.String(255), nullable=False, default='private')
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f'<File {self.filename}>'
