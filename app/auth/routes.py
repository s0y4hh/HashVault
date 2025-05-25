from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from . import auth_bp
from .forms import RegistrationForm, LoginForm, TwoFAForm
from ..models import User
from ..extensions import db, bcrypt, login_manager
import pyotp
import qrcode
import io
from flask import send_file
from flask_dance.contrib.google import make_google_blueprint, google
from sqlalchemy.exc import IntegrityError

# Google OAuth Blueprint
import os

google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile", "email"],
    redirect_url="/auth/google/callback"
)

@auth_bp.record_once
def on_load(state):
    state.app.register_blueprint(google_bp, url_prefix="/auth/google")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_pw)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('auth.login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists.', 'danger')
    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            if user.is_2fa_enabled:
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('auth.twofa'))
            login_user(user, remember=form.remember.data)
            return redirect(url_for('main.search'))
        flash('Invalid email or password.', 'danger')
    return render_template('auth/login.html', form=form)

@auth_bp.route('/2fa', methods=['GET', 'POST'])
def twofa():
    form = TwoFAForm()
    user_id = session.get('pre_2fa_user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(form.token.data):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            return redirect(url_for('main.search'))
        flash('Invalid 2FA code.', 'danger')
    return render_template('auth/2fa.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    # 2FA setup and API key management handled here
    if request.method == 'POST':
        if 'enable_2fa' in request.form:
            if not current_user.is_2fa_enabled:
                secret = pyotp.random_base32()
                current_user.twofa_secret = secret
                db.session.commit()
        elif 'disable_2fa' in request.form:
            current_user.is_2fa_enabled = False
            current_user.twofa_secret = None
            db.session.commit()
        elif 'regenerate_api_key' in request.form:
            import secrets
            current_user.api_key = secrets.token_urlsafe(32)
            db.session.commit()
    return render_template('auth/account.html')

@auth_bp.route('/2fa_qr')
@login_required
def twofa_qr():
    if not current_user.twofa_secret:
        return '', 404
    totp = pyotp.TOTP(current_user.twofa_secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="HashVault")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@auth_bp.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/oauth2/v2/userinfo')
    if resp.ok:
        info = resp.json()
        user = User.query.filter_by(email=info['email']).first()
        if not user:
            user = User(username=info['email'].split('@')[0], email=info['email'], google_id=info['id'], password_hash='')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('main.search'))
    flash('Google login failed.', 'danger')
    return redirect(url_for('auth.login'))
