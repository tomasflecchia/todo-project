from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL


# Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(message='Email field cannot be empty.')],
                        render_kw={"placeholder": "Email"})
    password = PasswordField('Password',
                             validators=[DataRequired(message='Password field cannot be empty.')],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')


# Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(message='Email field cannot be empty.')],
                        render_kw={"placeholder": "Email"})
    password = PasswordField('Password',
                             validators=[DataRequired(message='Password field cannot be empty.')],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField('Log in')