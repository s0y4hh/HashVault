from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from . import main_bp
from .forms import HashSearchForm
from ..models import File, Permission, History
from ..extensions import db

@main_bp.route('/', methods=['GET', 'POST'])
@login_required
def search():
    form = HashSearchForm()
    file_info = None
    error = None
    if form.validate_on_submit():
        file_hash = form.file_hash.data
        file = File.query.filter_by(file_hash=file_hash).first()
        if file:
            # Check permissions
            perm = Permission.query.filter_by(file_id=file.id).first()
            if perm.permission_type == 'public' or file.uploader_id == current_user.id or (perm.permission_type == 'specific' and current_user.username in (perm.specific_users or '')):
                file_info = file
            else:
                error = 'File not found or access denied.'
        else:
            error = 'File not found or access denied.'
    return render_template('main/search.html', form=form, file_info=file_info, error=error)

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # User's uploaded files
    files = File.query.filter_by(uploader_id=current_user.id).all()
    # Download and upload history
    download_history = History.query.filter_by(user_id=current_user.id, action='download').order_by(History.timestamp.desc()).all()
    upload_history = History.query.filter_by(user_id=current_user.id, action='upload').order_by(History.timestamp.desc()).all()
    return render_template('main/dashboard.html', files=files, download_history=download_history, upload_history=upload_history)
