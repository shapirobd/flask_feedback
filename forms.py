from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import InputRequired


class RegisterForm(FlaskForm):

    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

    email = StringField('Email', validators=[InputRequired()])

    first_name = StringField('First name', validators=[InputRequired()])
    last_name = StringField('Last name', validators=[InputRequired()])

    is_admin = BooleanField(
        'Please check this box if you are an administrator.')


class LoginForm(FlaskForm):

    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


class FeedbackForm(FlaskForm):

    title = StringField('Title', validators=[InputRequired()])
    content = TextAreaField('Content', validators=[
                            InputRequired()])
