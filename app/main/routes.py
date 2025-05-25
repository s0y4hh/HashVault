from flask import render_template, request, flash
from flask_login import login_required, current_user
from app.main import main_bp
from app.files.models import File

@main_bp.route('/')
@login_required
def index():
    return render_template('main/index.html')

@main_bp.route('/search', methods=['POST'])
@login_required
def search():
    hash_query = request.form.get('hash_query')
    if not hash_query:
        flash('Please enter a hash to search.', 'warning')
        return render_template('main/index.html')

    file = File.query.filter_by(file_hash=hash_query).first()
    if file:
        if file.permissions == 'public' or file.uploader_id == current_user.id:
            return render_template('main/search_result.html', file=file)
        else:
            flash('Access denied. You do not have permission to view this file.', 'danger')
    else:
        flash('File not found.', 'danger')

    return render_template('main/index.html')
