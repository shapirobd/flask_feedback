from flask import Flask, render_template, redirect, request, flash, session
from flask_debugtoolbar import DebugToolbarExtension
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError, DataError

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
    if 'username' in session:
        return redirect(f"/users/{session['username']}")

    form = RegisterForm()

    if form.validate_on_submit():

        new_user = User.register(form=form)
        db.session.add(new_user)

        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(
                'Username is already taken. Please try another.')
            return render_template('register.html', form=form)
        except DataError:
            if len(new_user.username) > 20:
                form.username.errors.append(
                    'Username may not exceed 20 characters. Please try another username.'
                )
            if len(new_user.email) > 50:
                form.email.errors.append(
                    'Username may not exceed 50 characters. Please try another email.'
                )
            if len(new_user.first_name) > 30:
                form.first_name.errors.append(
                    'First name may not exceed 20 characters. Please try another first name.'
                )
            if len(new_user.last_name) > 30:
                form.last_name.errors.append(
                    'Last name may not exceed 20 characters. Please try another last name.'
                )
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', 'success')
        return redirect(f"/users/{session['username']}")

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Show a form that when submitted will login a user. This form should accept a username and a password."""
    if 'username' in session:
        return redirect(f"/users/{session['username']}")

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form=form)
        if user:
            flash(f'Welcome back, {user.username}', 'primary')
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username/password']
    return render_template('login.html', form=form)


@app.route('/users/<string:username>')
def show_secret(username):
    if 'username' in session and username == session['username'] or User.query.get(session['username']).is_admin:
        user = User.query.get_or_404(username)
        logged_in_user = User.query.get(session['username'])
        users = User.query.all()
        feedbacks = Feedback.query.filter(Feedback.user != None)
        return render_template('secret.html', user=user, users=users, logged_in_user=logged_in_user, feedbacks=feedbacks)
    flash('Permission denied - please log in with the correct account.', 'danger')
    return redirect('/login')


@app.route('/logout')
def logout_user():
    session.pop('username')
    return redirect('/login')


@app.route('/users/<string:username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' in session and username == session['username'] or User.query.get(session['username']).is_admin:
        form = FeedbackForm()
        if form.validate_on_submit():
            title = form.title.data
            content = form.content.data

            new_feedback = Feedback(
                title=title, content=content, username=username)

            db.session.add(new_feedback)
            db.session.commit()

            return redirect(f'/users/{username}')
        users = User.query.all()
        logged_in_user = User.query.get(session['username'])
        return render_template('feedback_form.html', form=form, users=users, logged_in_user=logged_in_user, username=username)
    return redirect('/login')


@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    if 'username' in session and session['username'] == feedback.username or User.query.get(session['username']).is_admin:
        form = FeedbackForm()

        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data

            db.session.commit()

            return redirect(f"/users/{session['username']}")
        form.content.data = feedback.content
        users = User.query.all()
        logged_in_user = User.query.get(session['username'])
        return render_template('update_feedback_form.html', form=form, users=users, logged_in_user=logged_in_user, username=session['username'], feedback=feedback)
    return redirect('/login')


@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.username or User.query.get(session['username']).is_admin:

        db.session.delete(feedback)
        db.session.commit()

        return redirect(f"/users/{session['username']}")

    return redirect("/login")


@app.route('/users/<string:username>/delete', methods=['POST'])
def delete_user(username):
    user = User.query.get_or_404(username)

    if 'username' in session and session['username'] == username or User.query.get(session['username']).is_admin:
        db.session.delete(user)
        db.session.commit()
        if not User.query.get(session['username']).is_admin:
            session.pop("username")
            return redirect("/login")
        else:
            return redirect(f"/users/{session['username']}")
    return redirect("/login")
