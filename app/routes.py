import base64
from datetime import datetime, timedelta
import html
import os
import re
import time
import bleach
from flask_limiter import Limiter
from itsdangerous import URLSafeTimedSerializer
import qrcode
import io
from flask import Blueprint, Flask, flash, redirect, render_template, request, session, url_for
from redis import Redis
from flask_mail import Mail, Message
from .models import UPLOAD_FOLDER, User, Log, Post
from . import db, utility
from markupsafe import escape
import pyotp

routes_bp = Blueprint('routes', __name__)

MAX_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes=15)

app = Flask(__name__)
redis = Redis(host="redis", port=6379, decode_responses=True)
limiter = Limiter(
    app=app,
    key_func=lambda: utility.get_client_ip,
    storage_uri="redis://redis:6379"
)

app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
s = URLSafeTimedSerializer(os.getenv('CONFIG_SECRET'))

@routes_bp.route('/home', methods=['GET'])
@routes_bp.route('/', methods=['GET'])
def home():
    user_id = session.get("user_id")

    if not user_id or not db.session.get(User, user_id):
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('routes.login'))

    posts = Post.query.order_by(Post.timestamp.desc()).all()
    
    user = User.query.get(session['user_id'])
    return render_template("home.html", user=user, posts=posts)

@routes_bp.route('/user/<username>', methods=['GET'])
def user_profile(username):
    user_id = session.get("user_id")

    if not user_id or not db.session.get(User, user_id):
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('routes.login'))

    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).all()

    return render_template('user_profile.html', user=user, posts=posts)

@routes_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if 'user_id' in session:
        return redirect(url_for('routes.home'))
    
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    honeypot = request.form.get("honeypot", "")
    if honeypot:
        return "Suspicious activity detected.", 403
    
    username, email = utility.sanitize_input(username), utility.sanitize_input(email)

    ### input validation #######################
    if utility.calculate_entropy(password) < 28:
        flash("The password is too weak. ", "danger")
        return redirect(url_for('routes.register'))

    if not utility.is_valid_username(username) or not utility.is_valid_email(email):
        flash("Invalid username or email format.", "danger")
        return redirect(url_for('routes.register'))

    if not username or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for('routes.register'))
    
    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("A user with that username or email already exists.", "danger")
        return redirect(url_for('routes.register'))
    ############################################

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    totp_secret = pyotp.random_base32()
    new_user.set_totp_secret(totp_secret)

    db.session.add(new_user)
    db.session.commit()
    
    totp = pyotp.TOTP(new_user.get_totp_secret())
    qr_url = totp.provisioning_uri(name=username, issuer_name="weHaveTwitterAtHome")
    qr = qrcode.make(qr_url)

    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    flash("Registration successful! Scan the QR code below with Google Authenticator.", "success")
    
    return render_template('qr_code.html', qr_image=qr_base64)

@routes_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('routes.home'))
    
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email')
    password = request.form.get('password')
    totp_code = request.form.get('2FA')

    honeypot = request.form.get("honeypot", "")
    if honeypot:
        return "Suspicious activity detected.", 403

    email = utility.sanitize_input(email)
    #### input validation ######################
    if not utility.is_valid_email(email):
        flash("Invalid email format.", "danger")
        return redirect(url_for('routes.login'))
    ############################################

    if not email or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for('routes.login'))

    user = User.query.filter(User.email == email).first()
    
    delay = 0
    if user:
        delay = min(2 ** user.failed_attempts, 60)
        if delay:
            time.sleep(delay)

    if not user:
        flash("Incorrect email or password.", "danger")
        return redirect(url_for('routes.login'))

    user_agent = request.headers.get('User-Agent', 'Unknown')
    ip_address = utility.get_client_ip()

    if user.failed_attempts >= MAX_ATTEMPTS and datetime.now() < user.locked_until:
        flash("Too many failed login attempts. Please try again later.", "danger")
        return redirect(url_for('routes.login'))

    if not user.check_password(password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_ATTEMPTS:
            user.locked_until = datetime.now() + LOCK_TIME

        log = Log(user_id=user.id, login_attempt_timestamp=datetime.now(), success=False, ip=ip_address, user_agent=user_agent)
        db.session.add(log)
        db.session.commit()
        flash("Incorrect email or password.", "danger")
        return redirect(url_for('routes.login'))

    if not totp_code:
        flash("Please enter the 2FA code.", "danger")
        return redirect(url_for('routes.login'))

    totp = pyotp.TOTP(user.get_totp_secret())
    if not totp.verify(totp_code, valid_window=3):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_ATTEMPTS:
            user.locked_until = datetime.now() + LOCK_TIME

        log = Log(user_id=user.id, login_attempt_timestamp=datetime.now(), success=False, ip=ip_address, user_agent=user_agent)
        db.session.add(log)
        db.session.commit()
        flash("Invalid 2FA code.", "danger")
        return redirect(url_for('routes.login'))

    user.failed_attempts = 0
    user.locked_until = None

    log = Log(user_id=user.id, login_attempt_timestamp=datetime.now(), success=True, ip=ip_address, user_agent=user_agent)
    db.session.add(log)
    db.session.commit()
    session.clear()
    session['user_id'] = user.id
    flash("Login successful!", "success")
    
    return redirect(url_for('routes.home'))

@routes_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out!', 'success')
    return redirect(url_for('routes.login'))

@routes_bp.route('/post', methods=['POST'])
@limiter.limit("10 per minute")
def post_message():
    user_id = session.get("user_id")

    if not user_id or not db.session.get(User, user_id):
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('routes.login'))
    
    content = request.form.get('content', '')

    honeypot = request.form.get("honeypot", "")
    if honeypot:
        return "Suspicious activity detected.", 403

    if not content or len(content) > 500:
        flash(f"Post content must be between 1 and 500 characters.", "danger")
        return redirect(url_for('routes.home'))

    content = html.unescape(content)

    dangerous_characters = ["'", ";", "--", "#", "=", "%", "(", ")", "&", "|", "`"]

    safe_tags = ['b', 'i', 'u', 'strong', 'em', 'a']
    
    def sanitize_content(content):
        def replace_brackets(match):
            tag = match.group(1)
            if tag.lower() in safe_tags:
                return match.group(0)
            else:
                return f"&#x3c;{tag}&#x3e;"
        
        for char in dangerous_characters:
            if len(char) == 1:
                content = content.replace(char, f"&#x{ord(char):x};")
            else:
                content = content.replace(char, f"&#x{ord(char[0]):x};")

        content = re.sub(r"</?([a-zA-Z0-9]+)>", replace_brackets, content)
        
        return content

    content = sanitize_content(content)

    forbidden_words = [
        "select", "union", "insert", "update", "delete", 
        "drop", "alter", "create", "exec", "execute", 
        "1=1", "--", "#", ";", "xp_", "substring", "@@", 
        "version", "script"
    ]

    forbidden_pattern = r"\b(" + "|".join(map(re.escape, forbidden_words)) + r")\b"

    def replace_forbidden(match):
        word = match.group(0)
        return " ".join(word)

    flagged_content = re.sub(forbidden_pattern, replace_forbidden, content, flags=re.IGNORECASE)

    sanitized_content = bleach.clean(
        flagged_content,
        tags=['b', 'i', 'u', 'strong', 'em', 'a'],
        attributes={'a': ['href']},
        strip=True
    )

    user = User.query.get(session['user_id'])
    post = Post(user_id=user.id, content=sanitized_content, timestamp=datetime.now())

    post.sign()

    db.session.add(post)
    db.session.commit()

    flash("Post created successfully!", "success")
    return redirect(url_for('routes.home'))

@routes_bp.route('/delete_post/<int:post_id>', methods=['GET', 'POST'])
def delete_post(post_id):
    user_id = session.get("user_id")

    if not user_id or not db.session.get(User, user_id):
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('routes.login'))

    post = Post.query.get(post_id)
    if post:
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted successfully.", "success")
    else:
        flash("Post not found.", "danger")

    return redirect(url_for('routes.home'))

@routes_bp.route('/logs', methods=['GET', 'POST'])
def logs():
    user_id = session.get("user_id")

    if not user_id or not db.session.get(User, user_id):
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('routes.login'))
    
    if request.method == 'GET':
        return render_template('logs.html')

    logs = Log.query.filter_by(user_id=user_id).order_by(Log.login_attempt_timestamp.desc()).all()

    return render_template('logs.html', logs=logs)

@routes_bp.route('/change_password', methods=['GET', 'POST'])
@limiter.limit("2 per minute", methods=["POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        flash("You must be logged in to change your password.", "danger")
        return redirect(url_for('routes.login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        totp_code = request.form.get('totp_code')

        honeypot = request.form.get("honeypot", "")
        if honeypot:
            return "Suspicious activity detected.", 403

        if utility.calculate_entropy(new_password) < 28:
            flash("The password is too weak. ", "danger")
            return redirect(url_for('routes.change_password'))

        if not new_password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for('routes.change_password'))

        if not user.check_password(current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for('routes.change_password'))

        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for('routes.change_password'))

        totp = pyotp.TOTP(user.get_totp_secret())
        if not totp.verify(totp_code, valid_window=3):
            flash("Invalid 2FA code.", "danger")
            return redirect(url_for('routes.change_password'))

        user.set_password(new_password)
        db.session.commit()

        flash("Password changed successfully!", "success")
        return redirect(url_for('routes.home'))

    return render_template('change_password.html')

@routes_bp.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def forgot_password():
    if 'user_id' in session:
            flash("You are already logged in.", "info")
            return redirect(url_for('routes.home'))
    
    if request.method == 'POST':
        email = request.form.get('email')

        honeypot = request.form.get("honeypot", "")
        if honeypot:
            return "Suspicious activity detected.", 403

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "danger")
            return redirect(url_for('routes.forgot_password'))

        token = s.dumps(email, salt='password-reset')

        recovery_url = url_for('routes.restore_password', token=token, _external=True)
        msg = Message(
            subject="Password Recovery",
            sender="Test",
            recipients=[email],
            body=f"Click the link to reset your password: {recovery_url}",
        )
        try:
            mail.send(msg)
        except Exception as e:
            flash(f"Failed to send the recovery email: {str(e)}", "danger")

        flash("A recovery email has been sent to your email address.", "success")
        return redirect(url_for('routes.login'))

    return render_template('forgot_password.html')

@routes_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def restore_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except:
        flash("The recovery link is invalid or has expired.", "danger")
        return redirect(url_for('routes.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for('routes.reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        user.set_password(new_password)
        db.session.commit()

        totp = pyotp.TOTP(user.get_totp_secret())
        qr_url = totp.provisioning_uri(name=user.username, issuer_name="weHaveTwitterAtHome")
        qr = qrcode.make(qr_url)

        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        flash("Your password has been reset successfully!", "success")
        return render_template('qr_code.html', qr_image=qr_base64)

    return render_template('restore_password.html', token=token)

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many requests. Please wait a moment and try again.", "danger")
    return redirect(url_for('routes.login')), 429