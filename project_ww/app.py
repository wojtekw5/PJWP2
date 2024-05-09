from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import uuid

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, filename):
        self.filename = filename

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File!")

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
