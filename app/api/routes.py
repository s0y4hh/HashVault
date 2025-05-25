from flask import request, jsonify, url_for, current_app
from ..models import User, File, Permission
from ..extensions import db
from . import api_bp

@api_bp.route('/search', methods=['GET'])
def api_search():
    file_hash = request.args.get('hash')
    api_key = request.args.get('api_key')
    if not file_hash or not api_key:
        return jsonify({'error': 'Missing hash or api_key'}), 400
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({'error': 'Invalid API key'}), 403
    file = File.query.filter_by(file_hash=file_hash).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404
    perm = Permission.query.filter_by(file_id=file.id).first()
    if perm.permission_type != 'public':
        return jsonify({'error': 'Access denied'}), 403
    download_url = url_for('files.download', file_hash=file_hash, _external=True)
    return jsonify({
        'filename': file.filename,
        'file_hash': file.file_hash,
        'file_size': file.file_size,
        'file_type': file.file_type,
        'encryption_method': file.encryption_method,
        'download_url': download_url
    })
