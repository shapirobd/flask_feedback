from flask import Flask, render_template, redirect, request, flash, session
from flask_debugtoolbar import DebugToolbarExtension
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = 'flaskfeedbacksecretkey'

connect_db(app)

db.create_all()


@app.route('/')
def root():
    """Redirect to /register."""
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Show a form that when submitted will register/create a user.
    This form should accept a username, password, email, first_name, and last_name."""

    form = RegisterForm()

    # Process the registration form by adding a new user. Then redirect to / secret
    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        new_user = User.register(username=username, pwd=password,
                                 email=email, first_name=first_name, last_name=last_name)

        db.session.add(new_user)

        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(
                'Username is already taken. Please try another.')
            return render_template('register.html', form=form)

        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', 'success')
        return redirect(f'/users/{username}')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Show a form that when submitted will login a user. This form should accept a username and a password."""
    form = LoginForm()

    # Process the login form, ensuring the user is authenticated and going to / secret if so.
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username=username, pwd=password)

        if user:
            flash(f'Welcome back, {user.username}', 'primary')
            session['username'] = username
            return redirect(f'/users/{username}')
        else:
            form.username.errors = ['Invalid username/password']

    return render_template('login.html', form=form)


@app.route('/users/<string:username>')
def show_secret(username):
    if 'username' in session:
        user = User.query.get(username)
        feedbacks = user.feedbacks
        return render_template('secret.html', user=user, feedbacks=feedbacks)
    flash('Permission denied - please log in.', 'danger')
    return redirect('/login')


@app.route('/logout')
def logout_user():
    session.pop('username')
    return redirect('/login')


@app.route('/users/<string:username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' in session:
        form = FeedbackForm()
        if form.validate_on_submit():
            title = form.title.data
            content = form.content.data

            new_feedback = Feedback(
                title=title, content=content, username=username)

            db.session.add(new_feedback)
            db.session.commit()

            return redirect(f'/users/{username}')
        return render_template('feedback_form.html', form=form, username=username)
    return redirect('/login')


@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)

    if 'username' in session and session['username'] == feedback.username:
        form = FeedbackForm()

        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data

            db.session.commit()

            return redirect(f"/users/{session['username']}")
        form.content.data = feedback.content
        return render_template('update_feedback_form.html', form=form, username=session['username'], feedback=feedback)
    return redirect('/login')


@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)

    if 'username' in session and session['username'] == feedback.username:

        db.session.delete(feedback)
        db.session.commit()

        return redirect(f"/users/{session['username']}")

    return redirect("/login")


@app.route('/users/<string:username>/delete', methods=['POST'])
def delete_user(username):
    user = User.query.get(username)

    if 'username' in session and session['username'] == username:
        session.pop("username")
        db.session.delete(user)
        db.session.commit()

    return redirect("/login")
