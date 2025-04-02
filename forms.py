from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Image', validators=[Optional()])  # Optional field
    group_id = SelectField('Group', coerce=int)  # coerce to int for proper value handling
    submit = SubmitField('Create Post')