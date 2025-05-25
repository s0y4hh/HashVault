import os
import shutil
from flask import render_template, redirect, url_for, flash, request, send_from_directory, abort, jsonify, current_app
from flask_login import login_required, current_user
from . import files_bp
from .forms import FileUploadForm
from ..models import File, Permission, History, User
from ..extensions import db
from ..utils import (
    allowed_file, get_secure_filename, generate_sha256, generate_encryption_key, encrypt_file_aes256,
    encrypt_file_fernet, generate_fernet_key, encrypt_file_chacha20, generate_chacha20_key, pdf_password_protect
)
from werkzeug.utils import secure_filename
from datetime import datetime

@files_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = FileUploadForm()
    encryption_key = None
    if form.validate_on_submit():
        file = form.file.data
        if not allowed_file(file.filename):
            flash('File type not allowed.', 'danger')
            return redirect(request.url)
        filename = get_secure_filename(file.filename)
        temp_path = os.path.join('/tmp', filename)
        file.save(temp_path)
        file_hash = generate_sha256(temp_path)
        file_size = os.path.getsize(temp_path)
        file_type = filename.rsplit('.', 1)[1].lower()
        encryption_method = form.encryption_method.data
        final_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_hash)
        # Check for duplicate file hash
        if File.query.filter_by(file_hash=file_hash).first():
            flash('A file with the same content already exists.', 'danger')
            os.remove(temp_path)
            return redirect(request.url)
        # Encryption
        if encryption_method == 'aes256':
            encryption_key = generate_encryption_key()
            encrypt_file_aes256(temp_path, final_path, encryption_key)
        elif encryption_method == 'fernet':
            encryption_key = generate_fernet_key()
            encrypt_file_fernet(temp_path, final_path, encryption_key.encode())
        elif encryption_method == 'chacha20':
            encryption_key = generate_chacha20_key()
            encrypt_file_chacha20(temp_path, final_path, encryption_key)
        elif encryption_method == 'pdfpw' and file_type == 'pdf':
            pdf_password = form.pdf_password.data
            if not pdf_password:
                flash('PDF password required.', 'danger')
                os.remove(temp_path)
                return redirect(request.url)
            pdf_password_protect(temp_path, final_path, pdf_password)
        else:
            shutil.move(temp_path, final_path)
        # Permissions
        permission_type = form.permission.data
        specific_users = form.specific_users.data if permission_type == 'specific' else None
        # Save file record
        new_file = File(
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type,
            encryption_method=encryption_method,
            encryption_key=encryption_key,
            uploader_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        # Save permissions
        perm = Permission(
            file_id=new_file.id,
            user_id=current_user.id,
            permission_type=permission_type,
            specific_users=specific_users
        )
        db.session.add(perm)
        # Log upload
        history = History(user_id=current_user.id, file_id=new_file.id, action='upload', file_hash=file_hash, filename=filename)
        db.session.add(history)
        db.session.commit()
        flash('File uploaded successfully.', 'success')
        return render_template('files/upload.html', form=form, encryption_key=encryption_key)
    return render_template('files/upload.html', form=form, encryption_key=encryption_key)

@files_bp.route('/download/<file_hash>')
@login_required
def download(file_hash):
    file = File.query.filter_by(file_hash=file_hash).first_or_404()
    perm = Permission.query.filter_by(file_id=file.id).first()
    # Permission logic: Only uploader for private, public for all, specific for listed users
    if perm.permission_type == 'private':
        if file.uploader_id != current_user.id:
            abort(403)
    elif perm.permission_type == 'specific':
        allowed_users = [u.strip() for u in (perm.specific_users or '').split(',') if u.strip()]
        if file.uploader_id != current_user.id and current_user.username not in allowed_users:
            abort(403)
    # Log download
    history = History(user_id=current_user.id, file_id=file.id, action='download', file_hash=file_hash, filename=file.filename)
    db.session.add(history)
    db.session.commit()
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], file_hash, as_attachment=True, download_name=file.filename)

@files_bp.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_file_page():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        algorithm = request.form.get('algorithm')
        key = request.form.get('key')
        pdf_password = request.form.get('pdf_password')
        if not uploaded_file or not algorithm:
            flash('File and algorithm are required.', 'danger')
            return redirect(request.url)
        temp_path = os.path.join('/tmp', get_secure_filename(uploaded_file.filename))
        uploaded_file.save(temp_path)
        output_path = temp_path + '.decrypted'
        try:
            if algorithm == 'aes256':
                from ..utils import decrypt_file_aes256
                decrypt_file_aes256(temp_path, output_path, key)
            elif algorithm == 'fernet':
                from ..utils import decrypt_file_fernet
                decrypt_file_fernet(temp_path, output_path, key.encode())
            elif algorithm == 'chacha20':
                from ..utils import decrypt_file_chacha20
                decrypt_file_chacha20(temp_path, output_path, key)
            elif algorithm == 'pdfpw':
                import PyPDF2
                try:
                    reader = PyPDF2.PdfReader(temp_path)
                    if not pdf_password:
                        flash('PDF password required.', 'danger')
                        os.remove(temp_path)
                        return redirect(request.url)
                    if not reader.is_encrypted:
                        flash('PDF is not encrypted.', 'danger')
                        os.remove(temp_path)
                        return redirect(request.url)
                    if reader.decrypt(pdf_password) == 0:
                        flash('Incorrect PDF password.', 'danger')
                        os.remove(temp_path)
                        return redirect(request.url)
                    writer = PyPDF2.PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    with open(output_path, 'wb') as fout:
                        writer.write(fout)
                except Exception as e:
                    flash(f'PDF decryption failed: {e}', 'danger')
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    return redirect(request.url)
            else:
                flash('Unsupported algorithm.', 'danger')
                os.remove(temp_path)
                return redirect(request.url)
            return send_from_directory('/tmp', os.path.basename(output_path), as_attachment=True, download_name='decrypted_' + uploaded_file.filename)
        except Exception as e:
            flash(f'Decryption failed: {e}', 'danger')
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(output_path):
                os.remove(output_path)
            return redirect(request.url)
    return render_template('files/decrypt.html')

@files_bp.route('/view_key/<file_hash>', methods=['POST'])
@login_required
def view_key(file_hash):
    password = request.form.get('password')
    file = File.query.filter_by(file_hash=file_hash, uploader_id=current_user.id).first_or_404()
    from ..extensions import bcrypt
    if not bcrypt.check_password_hash(current_user.password_hash, password):
        return jsonify({'error': 'Invalid password'}), 403
    # Only return key if file is encrypted
    if file.encryption_method in ['aes256', 'fernet', 'chacha20']:
        return jsonify({'key': file.encryption_key})
    return jsonify({'error': 'No encryption key for this file.'}), 400
