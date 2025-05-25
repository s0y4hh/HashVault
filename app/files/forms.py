from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Optional

class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    permission = SelectField('File Permissions', choices=[('private', 'Private'), ('public', 'Public'), ('specific', 'Specific Users')], default='private')
    specific_users = StringField('Specific Users (comma-separated usernames)', validators=[Optional()])
    encryption_method = SelectField('Encryption Method', choices=[('none', 'None'), ('aes256', 'AES-256 Encryption'), ('pdfpw', 'PDF Password Protection')], default='none')
    pdf_password = StringField('PDF Password (if PDF)', validators=[Optional()])
    submit = SubmitField('Upload')
