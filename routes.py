# routes.py
from flask import render_template, request, redirect, url_for, send_from_directory, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import Report, User  # Import the User model from models.py
import os
import uuid
from datetime import datetime

# Set allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx'}

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def setup_routes(app):
    from app import db  # Import db here to avoid circular import

    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/users', methods=['GET', 'POST'])
    def manage_users():
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            role = request.form.get('role')
            password = request.form.get('password')

            # Basic form validation
            if not name or not email or not password:
                flash('Please fill in all required fields!', 'danger')
                return redirect(url_for('manage_users'))

            # Hash the password
            password_hash = generate_password_hash(password)

            # Create new user
            new_user = User(
                name=name,
                email=email,
                role=role,
                password_hash=password_hash
            )

            # Add user to the database
            db.session.add(new_user)
            db.session.commit()

            flash('User created successfully!', 'success')
            return redirect(url_for('manage_users'))

        users = User.query.all()
        return render_template('users.html', users=users)

    @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
    def edit_user(user_id):
        user = User.query.get_or_404(user_id)
        if request.method == 'POST':
            user.name = request.form.get('name')
            user.email = request.form.get('email')
            user.role = request.form.get('role')

            # Save changes
            db.session.commit()

            flash('User details updated successfully!', 'success')
            return redirect(url_for('manage_users'))
        
        return render_template('edit_user.html', user=user)

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()

        flash('User deleted successfully!', 'success')
        return redirect(url_for('manage_users'))

    # Function to generate a unique access code
    def generate_access_code():
        return str(uuid.uuid4().hex[:6])  # First 6 characters of the UUID

    @app.route('/submit', methods=['POST'])
    def submit_report():
        # Get form data
        report_type = request.form.get('report_type')
        report_details = request.form.get('report_details')
        anonymous_contact = request.form.get('anonymous_contact')
        password = request.form.get('password')
        
        # Handle different issue types
        issue_details = {}

        # Specific fields based on report type
        if report_type == "Harassment":
            issue_details['type_of_harassment'] = request.form.get('harassmentType')
            issue_details['harassment_frequency'] = request.form.get('frequency')
            issue_details['witnesses'] = request.form.get('witnesses')
            issue_details['previous_report'] = request.form.get('previousReport')
            if request.form.get('previousReport') == 'yes':
                issue_details['reported_to'] = request.form.get('reportedTo')
                issue_details['previous_response'] = request.form.get('previousResponse')

        elif report_type == "Fraud":
            issue_details['fraud_details'] = request.form.get('fraudDetails')
            issue_details['fraud_involved'] = request.form.get('fraudInvolved')
            issue_details['fraud_date'] = request.form.get('fraudDate')

        elif report_type == "Discrimination":
            issue_details['discrimination_details'] = request.form.get('discriminationDetails')
            issue_details['discrimination_basis'] = request.form.get('discriminationBasis')

        elif report_type == "Safety_Violation":
            issue_details['safety_violation_details'] = request.form.get('safetyViolationDetails')
            issue_details['safety_violation_date'] = request.form.get('safetyViolationDate')

        elif report_type == "Conflict_of_Interest":
            issue_details['conflict_details'] = request.form.get('conflictDetails')
            issue_details['conflict_involved'] = request.form.get('conflictInvolved')

        elif report_type == "Bribery":
            issue_details['bribery_details'] = request.form.get('briberyDetails')
            issue_details['bribery_involved'] = request.form.get('briberyInvolved')

        elif report_type == "Environmental_Violation":
            issue_details['environment_violation_details'] = request.form.get('environmentViolationDetails')
            issue_details['environment_violation_date'] = request.form.get('environmentViolationDate')

        elif report_type == "Mismanagement":
            issue_details['mismanagement_details'] = request.form.get('mismanagementDetails')
            issue_details['mismanagement_responsible'] = request.form.get('mismanagementResponsible')

        elif report_type == "Other":
            issue_details['other_details'] = request.form.get('otherDetails')

        # Handle file upload
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            issue_details['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Optionally handle anonymous contact and password
        if anonymous_contact:
            issue_details['anonymous_contact'] = anonymous_contact
        if password:
            issue_details['password'] = password

        # Generate access code
        access_code = generate_access_code()

        # In a real application, you would save `issue_details` to a database.
        # For now, we'll just flash a success message.
        flash('Report submitted successfully', 'success')

        # Redirect to a confirmation page or the home page
        return render_template("confirmation.html",access_code=access_code)

    @app.route('/confirmation')
    def confirmation():
        return render_template('confirmation.html')

    @app.route('/uploads/<filename>')
    def download_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route('/dashboard')
    def dashboard():
        page = request.args.get('page', 1, type=int)
        reports = Report.query.order_by(Report.timestamp.desc()).paginate(page=page, per_page=5, error_out=False)

        new_reports_count = Report.query.filter(Report.status == 'New').count()
        ongoing_investigations_count = Report.query.filter(Report.status == 'Ongoing').count()
        resolved_cases_count = Report.query.filter(Report.status == 'Resolved').count()

        return render_template('investigator_dashboard.html', 
                               new_reports=new_reports_count, 
                               ongoing_investigations=ongoing_investigations_count, 
                               resolved_cases=resolved_cases_count,
                               reports=reports)

    
    @app.route('/reports')
    def view_reports():
        reports = Report.query.filter(Report.status == 'New').all()
        return render_template('reports.html', reports=reports)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            # Query the database for the user by email
            user = User.query.filter_by(email=email).first()

            # Initialize error messages
            error_email = None
            error_password = None

            # Check if user exists and if the password matches
            if not user:
                error_email = "No account found with this email."
            elif not check_password_hash(user.password_hash, password):
                error_password = "Incorrect password. Please try again."

            if error_email or error_password:
                # Return the login page with error messages
                return render_template('login.html', error_email=error_email, error_password=error_password)

            # If credentials are valid, store session and redirect
            session['user_id'] = user.id
            session['role'] = user.role  # Optionally store user role
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or other page

        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        session.clear()  # Clear the session data
        
        # Redirect the user to the homepage or login page after logout
        return redirect(url_for('index'))  # Or replace 'index' with 'login' if you have a login route
    
    @app.route('/reports', methods=['GET'])
    def reports():
        # Get filters from request arguments
        status = request.args.get('status', '')
        report_type = request.args.get('report_type', '')
        search = request.args.get('search', '')

        # Query reports with optional filters
        query = Report.query
        if status:
            query = query.filter_by(status=status)
        if report_type:
            query = query.filter_by(report_type=report_type)
        if search:
            query = query.filter(Report.id == search)  # Search by Report ID
        
        reports = query.paginate(page=request.args.get('page', 1, type=int), per_page=10)

        return render_template('reports.html', reports=reports.items)
    
    # Initialize Flask-Mail and URLSafeTimedSerializer
    #mail = Mail()
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    @app.route('/reset_password', methods=['GET', 'POST'])
    def reset_password():
        if request.method == 'POST':
            email = request.form.get('email')

            # Find the user by email
            user = User.query.filter_by(email=email).first()  # Replace with your User model
            if not user:
                return render_template('reset_password.html', error="Email not found")

            # Generate password reset token
            token = s.dumps(email, salt='password-reset')

            # Display the reset link directly (for testing without email)
            link = url_for('reset_token', token=token, _external=True)
            return f"Reset link: <a href='{link}'>{link}</a>"

        return render_template('reset_password.html')


    @app.route('/reset/<token>', methods=['GET', 'POST'])
    def reset_token(token):
        try:
            email = s.loads(token, salt='password-reset', max_age=3600)  # Token expires after 1 hour
        except SignatureExpired:
            return "The token has expired. Please request a new one.", 400

        if request.method == 'POST':
            new_password = request.form.get('password')

            # Find the user by email and update their password
            user = User.query.filter_by(email=email).first()  # Replace with your User model
            if user:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                return "Your password has been reset successfully!"

        return render_template('reset_form.html')