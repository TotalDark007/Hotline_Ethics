from extensions import db  # Import db from extensions.py
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets 

class Report(db.Model):
    __tablename__ = 'report'
    __table_args__ = {'extend_existing': True}  # Allow redefining the table if necessary

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp of the report submission
    status = db.Column(db.String(50))  # 'New', 'Ongoing', 'Resolved'
    report_type = db.Column(db.String(100), nullable=False)  # Type of the report (e.g., Fraud, Safety)
    report_details = db.Column(db.String(500), nullable=False)  # Detailed description of the report
    anonymous_contact = db.Column(db.String(100), nullable=True)  # Optional anonymous contact information
    access_code = db.Column(db.String(100), unique=True, nullable=False)  # Unique access code for each report
    password_hash = db.Column(db.String(100), nullable=False)  # Hashed password for the report
    file_name = db.Column(db.String(255), nullable=True)  # Store the filename of the uploaded file

    # Additional fields for harassment
    harassment_details = db.Column(db.String(1000), nullable=True)  # Detailed harassment incident description
    harassment_type = db.Column(db.String(100), nullable=True)  # Type of harassment (verbal, physical, etc.)
    harassment_frequent = db.Column(db.String(100), nullable=True)  # Frequency of harassment
    harassment_witnesses = db.Column(db.String(255), nullable=True)  # Witnesses to the harassment
    harassment_previous_reports = db.Column(db.String(100), nullable=True)  # Whether it has been reported before
    harassment_reporting_person = db.Column(db.String(255), nullable=True)  # Person to whom the incident was reported
    harassment_response = db.Column(db.String(1000), nullable=True)  # Response to previous reports

    # Additional fields for fraud, discrimination, etc. 
    fraud_details = db.Column(db.String(1000), nullable=True)
    fraud_involved = db.Column(db.String(255), nullable=True)
    fraud_date = db.Column(db.String(100), nullable=True)

    discrimination_details = db.Column(db.String(1000), nullable=True)
    discrimination_basis = db.Column(db.String(255), nullable=True)

    safety_violation_details = db.Column(db.String(1000), nullable=True)
    safety_violation_date = db.Column(db.String(100), nullable=True)

    conflict_details = db.Column(db.String(1000), nullable=True)
    conflict_involved = db.Column(db.String(255), nullable=True)

    bribery_details = db.Column(db.String(1000), nullable=True)
    bribery_involved = db.Column(db.String(255), nullable=True)

    environment_violation_details = db.Column(db.String(1000), nullable=True)
    environment_violation_date = db.Column(db.String(100), nullable=True)

    mismanagement_details = db.Column(db.String(1000), nullable=True)
    mismanagement_responsible = db.Column(db.String(255), nullable=True)

    other_details = db.Column(db.String(1000), nullable=True)

    def __repr__(self):
        return f'<Report {self.id}>'

    # Method to generate a unique access code
    def generate_access_code(self):
        return secrets.token_urlsafe(16)  # Generates a URL-safe token (string)

    # Method to set the password (after hashing it)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check if the password matches the stored hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False, default='investigator')  # 'investigator' or 'admin'
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.email}, Name {self.name}, Role {self.role}>'

    def set_password(self, password):
        """Hashes the password for storage."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def create_admin_user():
        """Method to create an admin user."""
        admin_user = User.query.filter_by(role='admin').first()
        if not admin_user:
            admin_user = User(
                name="Admin",
                email="admin@domain.com",
                role="admin"
            )
            admin_user.set_password("adminpassword")  # Set a strong password for admin user
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")

