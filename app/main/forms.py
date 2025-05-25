from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class HashSearchForm(FlaskForm):
    file_hash = StringField('Search file hash', validators=[DataRequired(), Length(min=64, max=64)])
    submit = SubmitField('Search')
