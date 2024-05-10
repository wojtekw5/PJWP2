import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import uuid
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms.fields.simple import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from config import Config
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config.from_object(Config)

# Inicjalizacja CSRFProtect
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Model User
class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return self.user_id

# Model File
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, filename):
        self.filename = filename

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Formularz rejestracyjny
class RegistrationForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    confirm_password = PasswordField('Potwierdź hasło', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Zarejestruj się')

# Formularz logowania
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')

# Formularz przesyłania plików
class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File!")

@app.route('/', methods=["GET", "POST"])
@app.route('/home', methods=["GET", "POST"])
@login_required
def home():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data
        original_filename = secure_filename(file.filename)

        # Ensure the upload folder exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        # Ensure filename is unique in the storage
        base_filename, file_extension = os.path.splitext(original_filename)
        unique_filename = original_filename
        counter = 1
        while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)):
            unique_filename = f"{base_filename}_{counter}{file_extension}"
            counter += 1

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Add new file entry to the database
        new_file = File(filename=unique_filename)
        db.session.add(new_file)
        db.session.commit()

        flash('File uploaded successfully', 'success')
        app.logger.info(f'File {unique_filename} uploaded successfully.')
        return redirect(url_for('home'))

    # Retrieve all files from the database
    files = File.query.all()
    return render_template('index.html', form=form, files=files)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        app.logger.info(f'Attempting login for email: {email}')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            app.logger.info('Login successful')
            login_user(user)
            flash('Zalogowano pomyślnie!', 'success')
            return redirect(url_for('home'))
        else:
            app.logger.warning('Login failed: Invalid email or password')
            flash('Błędny email lub hasło.', 'danger')
    else:
        # Logowanie błędów walidacji
        app.logger.info(f'Form validation failed: {form.errors}')
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Rejestracja zakończona sukcesem!', 'success')
            app.logger.info(f'User {username} registered successfully.')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Error registering user {username}: {str(e)}')
            if 'UNIQUE constraint failed: user.username' in str(e.orig):
                flash('Nazwa użytkownika jest już zajęta. Wybierz inną.', 'danger')
            elif 'UNIQUE constraint failed: user.email' in str(e.orig):
                flash('Adres email jest już używany. Użyj innego.', 'danger')

    else:
        app.logger.info(f'Form validation failed: {form.errors}')
    return render_template('register.html', form=form)

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

@app.route('/delete/<file_id>', methods=["POST"])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
        app.logger.error(f'Error deleting file {file.filename}: {str(e)}')
        return redirect(url_for('home'))

    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    app.logger.info(f'File {file.filename} deleted successfully.')
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Wylogowano pomyślnie!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
