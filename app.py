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
    app = Flask(__name__)

    # Configure app settings
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'csv', 'docx'}
    app.config['SECRET_KEY'] = os.urandom(24)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Import and set up routes
    from routes import setup_routes
    setup_routes(app)

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
        return render_template('view_report.html', report=report, file_path=file_path)
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
