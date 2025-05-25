from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager, bcrypt
from app.auth import auth_bp
from app.auth.models import User
from app.auth.forms import RegistrationForm, LoginForm
import pyotp

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if not current_user.two_factor_secret:
        current_user.generate_2fa_secret()
        db.session.commit()
    totp = pyotp.TOTP(current_user.two_factor_secret)
    qr_code_url = totp.provisioning_uri(name=current_user.email, issuer_name="HashVault")
    return render_template('auth/setup_2fa.html', qr_code_url=qr_code_url)

@auth_bp.route('/2fa/verify', methods=['POST'])
@login_required
def verify_2fa():
    token = request.form.get('token')
    if current_user.verify_2fa(token):
        session['2fa_verified'] = True
        flash('Two-factor authentication verified!', 'success')
        return redirect(url_for('main.index'))
    else:
        flash('Invalid token. Please try again.', 'danger')
        return redirect(url_for('auth.setup_2fa'))
