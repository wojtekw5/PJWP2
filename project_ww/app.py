import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import uuid

from wtforms.fields.simple import StringField, PasswordField
from wtforms.validators import DataRequired, Email

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, filename):
        self.filename = filename

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File!")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')


@app.route('/', methods=["GET", "POST"])
@app.route('/home', methods=["GET", "POST"])
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
        # Here you should add code to verify the user credentials
        # For example, query the user from the database
        # user = User.query.filter_by(email=email).first()
        # if user and check_password_hash(user.password, password):
        #     flash('Logged in successfully.', 'success')
        #     return redirect(url_for('home'))
        # else:
        #     flash('Invalid email or password.', 'danger')

        flash('Login attempt with email: {}'.format(email), 'info')
        return redirect(url_for('home'))

    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Hasła muszą być identyczne.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            if 'UNIQUE constraint failed: user.username' in str(e.orig):
                flash('Nazwa użytkownika jest już zajęta. Wybierz inną.', 'danger')
            elif 'UNIQUE constraint failed: user.email' in str(e.orig):
                flash('Adres email jest już używany. Użyj innego.', 'danger')

    return render_template('register.html')

@app.route('/download/<file_id>')
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

@app.route('/delete/<file_id>', methods=["POST"])
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
        return redirect(url_for('home'))

    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
