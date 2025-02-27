from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_mail import Mail
import os
from flask_migrate import Migrate

load_dotenv()
db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('CONFIG_SECRET')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    mail.init_app(app)
    db.init_app(app)

    migrate = Migrate(app, db)

    from .models import User, Post, Log

    from .routes import routes_bp
    app.register_blueprint(routes_bp)

    return app