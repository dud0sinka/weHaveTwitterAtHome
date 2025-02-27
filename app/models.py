import hashlib
import hmac
from . import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
SECRET_KEY = os.getenv('CONFIG_SECRET')

key = os.getenv('FERNET_KEY')
if key:
    key = key.encode('utf-8')
    try:
        fernet = Fernet(key)
    except ValueError as e:
        print(f"Invalid key: {e}")
else:
    print("FERNET_KEY not found in .env")

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(200), nullable=False)

    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def set_totp_secret(self, totp_secret):
        encrypted_secret = fernet.encrypt(totp_secret.encode())
        self.totp_secret = encrypted_secret.decode()

    def get_totp_secret(self):
        decrypted_secret = fernet.decrypt(self.totp_secret.encode())
        return decrypted_secret.decode()

    def login_attempt(self, success, ip):
        self.success = success
        self.ip = ip
        self.login_attempt_timestamp = datetime.now()

        if success:
            self.failed_attempts = 0
            self.locked_until = None
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= 5:
                self.locked_until = datetime.now() + timedelta(minutes=5)

class Log(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    login_attempt_timestamp = db.Column(db.DateTime, nullable=True)
    success = db.Column(db.Boolean, nullable=True)
    ip = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)

class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    signature = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

    def generate_signature(self):
        data = f"{self.user_id}:{self.content}:{self.timestamp}"
        return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self):
        return hmac.compare_digest(self.signature, self.generate_signature())

    def sign(self):
        self.signature = self.generate_signature()
