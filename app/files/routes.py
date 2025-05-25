from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.files import files_bp
from app.files.models import File
from app import db
import os
import hashlib
from cryptography.fernet import Fernet

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'uploads/'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@files_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)

            # Save file temporarily to calculate hash
            file.save(file_path)
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Encrypt file if encryption is selected
            encryption_key = None
            if request.form.get('encryption') == 'aes-256':
                encryption_key = Fernet.generate_key().decode()
                cipher = Fernet(encryption_key)
                with open(file_path, 'rb') as f:
                    encrypted_data = cipher.encrypt(f.read())
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)

            # Save file metadata to database
            new_file = File(
                filename=filename,
                file_hash=file_hash,
                uploader_id=current_user.id,
                encryption_algorithm='AES-256' if encryption_key else None,
                encryption_key=encryption_key,
                permissions=request.form.get('permissions', 'private')
            )
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid file type or no file selected.', 'danger')

    return render_template('files/upload.html')
