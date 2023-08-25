from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Email, EqualTo, Length
from wtforms.fields import FileField


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        InputRequired(message="Email is required"),
                        Email(message='Invalid email address')
                        ], render_kw={"placeholder": "Email"})

    password = PasswordField('Password', validators=[
        InputRequired(message="Password is required")
    ], render_kw={"placeholder": "Password"})

    submit = SubmitField('Submit')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
                        InputRequired(message="Email is required"),
                        Email(message='Invalid email address')
                        ], render_kw={"placeholder": "Email"})

    password = PasswordField('Password', validators=[
        InputRequired(message="Password is required"),
        Length(min=6)
    ], render_kw={"placeholder": "Password"})

    confirm_password = PasswordField('Confirm password', validators=[
        InputRequired(message="Repeat password is required"),
        EqualTo('password')
    ], render_kw={"placeholder": "Repeat password"})

    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])

    submit = SubmitField('Register user')