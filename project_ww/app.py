from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
from config import Config
from models import db, File

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File!")

@app.route('/', methods=["GET", "POST"])
@app.route('/view_files')
def view_files():
    files = File.query.all()
    return render_template('view_files.html', files=files)
@app.route('/home', methods=["GET", "POST"])
def home():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        file.save(file_path)
        new_file = File(filename=filename)
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded successfully', 'success')
        return redirect(url_for('home'))
    return render_template('index.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Tworzy tabele w bazie danych
    app.run(debug=True)
