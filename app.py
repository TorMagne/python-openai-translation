import os
from flask import Flask, url_for, render_template, flash, redirect, request
from dotenv import load_dotenv
from webforms import LoginForm, RegistrationForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager
from flask_migrate import Migrate

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
app.config['SECRET_KEY'] = os.environ.get('FORM_KEY')

db = SQLAlchemy(app)
# migrate changes of a schema to the db
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(120), default='user')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # create a string
    def __repr__(self):
        return f'<User {self.email}>'


# login page
@app.route("/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    email = None
    password = None
    errors = None

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            existing_user = Users.query.filter_by(email=email).first()
            if existing_user and check_password_hash(existing_user.password_hash, password):
                login_user(existing_user)
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password. Please try again.", 'error')

        except IntegrityError:
            # Handle database integrity errors (e.g., unique constraint violation)
            db.session.rollback()  # Rollback the transaction
            print("An error occurred during registration. Please try again.", 'error')
    else:
        errors = form.errors

    return render_template('auth/login.html',
                           form=form,
                           email=email,
                           password=password,
                           errors=errors
                           )


# logout
@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    email = None
    password = None
    errors = None

    users = Users.query.all()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        selected_role = form.role.data

        try:
            existing_user = Users.query.filter_by(email=email).first()
            if existing_user:
                print("Email already in use. Please choose another.", 'error')

            else:
                hashed_password = generate_password_hash(password)
                new_user = Users(
                    email=email, password_hash=hashed_password, role=selected_role)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('register'))
                print("Registration successful. You can now log in.", 'success')
        except IntegrityError:
            # Handle database integrity errors (e.g., unique constraint violation)
            db.session.rollback()  # Rollback the transaction
            print("An error occurred during registration. Please try again.", 'error')
    else:
        errors = form.errors

    return render_template('auth/register.html', form=form, email=email, password=password, errors=errors, users=users)


@app.route("/delete_user/<int:user_id>", methods=['POST'])
# @login_required
def delete_user(user_id):
    try:
        # get user from db
        user = Users.query.get(user_id)

        # check if user exists
        if user:
            # delete the user from db
            db.session.delete(user)
            db.session.commit()
            print("user deleted")
        else:
            print("something went wrong")
    except IntegrityError:
        db.session.rollback()  # Rollback the transaction
        print("something went wrong when deleting the user")

    return redirect(url_for('register'))


# dashboard page
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html')


# translation page
@app.route("/translation")
@login_required
def translation():
    return render_template('translation.html')


# invalid url
@app.errorhandler(404)
def page_not_found(error):
    return render_template('/errors/404.html'), 404


# internal server error
@app.errorhandler(500)
def special_exception_handler(error):
    return render_template('/errors/500.html'), 500
