from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from models import Report
from extensions import db, migrate  # Import db and migrate from extensions.py
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

# Function to create the app
def create_app():
    # Resolve paths relative to this file to avoid CWD issues
    base_dir = os.path.abspath(os.path.dirname(__file__))
    templates_path = os.path.join(base_dir, 'templates')
    static_path = os.path.join(base_dir, 'static')
    uploads_path = os.path.join(base_dir, 'uploads')

    # Ensure Flask knows exactly where templates live
    app = Flask(__name__, template_folder=templates_path, static_folder=static_path)

    # Configure app settings
    # Use absolute path to the instance DB so migrations and app agree
    instance_db_path = os.path.join(base_dir, 'instance', 'reports.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{instance_db_path}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Use absolute path so uploads work regardless of CWD
    app.config['UPLOAD_FOLDER'] = uploads_path
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'csv', 'docx'}
    app.config['SECRET_KEY'] = os.urandom(24)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Import and set up routes
    from routes import setup_routes
    setup_routes(app)
    @app.after_request
    def add_no_cache_headers(response):
        # Prevent authenticated pages from being restored via back/forward cache
        # Also discourage intermediary caching. Keep static assets cacheable.
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            # Help proxies/browsers vary by auth state
            response.headers['Vary'] = (response.headers.get('Vary', '') + ', Cookie').strip(', ')
        return response

    return app

# Create the app instance
app = create_app()

# Function to check if the file type is allowed
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'csv', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


# Create tables in the database (this will be called before the first request)
@app.before_first_request
def create_tables():
    # This should be used only if you don't use migrations
    # db.create_all()  # Avoid using this for production environments
    pass

@app.route('/view_report', methods=['POST'])
def view_report():
    # Get the access code and password entered by the user
    access_code = request.form.get('access_code')
    password = request.form.get('password')

    # Find the report by access code
    report = Report.query.filter_by(access_code=access_code).first()

    # Check if the report exists and if the password matches
    if report and report.check_password(password):
        # If the report is found and password matches, show the report details
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], report.file_name) if report.file_name else None
        return render_template('public/view_report.html', report=report, file_path=file_path)
    else:
        # If the report is not found or password doesn't match
        return "Invalid access code or password. Please try again.", 400


def get_recent_reports(status=None, limit=5):
    query = Report.query
    if status:
        query = query.filter_by(status=status)  # Filter by status if provided
    reports = query.order_by(Report.timestamp.desc()).limit(limit).all()
    return reports

if __name__ == '__main__':
    app.run(debug=True)


