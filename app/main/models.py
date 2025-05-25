from app import db
from sqlalchemy.sql import func

class History(db.Model):
    __tablename__ = 'history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # e.g., 'upload', 'download'
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f'<History {self.action}>'
