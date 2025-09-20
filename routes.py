# routes.py
from flask import render_template, request, redirect, url_for, send_from_directory, flash, session, make_response
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import Report, User  # Import the User model from models.py
import os
import io
import csv
import uuid
from datetime import datetime, timedelta
import re

# Set allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx'}

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def setup_routes(app):
    from app import db  # Import db here to avoid circular import
 
    @app.route('/')
    def index():
        return render_template('public/index.html')
    
    @app.route('/users', methods=['GET', 'POST'])
    def manage_users():
        # Require login (admin preferred for user management)
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            role = (request.form.get('role') or 'investigator').strip().lower()
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
        return render_template('dashboard/users.html', users=users)

    @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
    def edit_user(user_id):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        user = User.query.get_or_404(user_id)
        if request.method == 'POST':
            user.name = request.form.get('name')
            user.email = request.form.get('email')
            user.role = request.form.get('role')

            # Save changes
            db.session.commit()

            flash('User details updated successfully!', 'success')
            return redirect(url_for('manage_users'))
        
        return render_template('dashboard/edit_user.html', user=user)

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    def delete_user(user_id):
        if not session.get('user_id'):
            return redirect(url_for('login'))
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
        # Required core fields
        report_type = (request.form.get('report_type') or '').strip()
        report_details = (request.form.get('report_details') or '').strip()
        anonymous_contact = (request.form.get('anonymous_contact') or '').strip() or None
        password = (request.form.get('password') or '').strip()

        if not report_type or not report_details or not password:
            flash('Please fill out report type, details, and password.', 'danger')
            return redirect(url_for('index'))

        # Create Report model instance
        access_code = generate_access_code()
        report = Report(
            status='New',
            report_type=report_type,
            report_details=report_details,
            anonymous_contact=anonymous_contact,
            access_code=access_code,
        )
        report.set_password(password)

        # File upload (optional)
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            report.file_name = filename

        # Map additional fields based on report type
        if report_type == "Harassment":
            report.harassment_type = request.form.get('harassmentType') or None
            report.harassment_frequent = request.form.get('frequency') or None
            report.harassment_witnesses = request.form.get('witnesses') or None
            prev = request.form.get('previousReport') or None
            report.harassment_previous_reports = prev
            if prev == 'yes':
                report.harassment_reporting_person = request.form.get('reportedTo') or None
                report.harassment_response = request.form.get('previousResponse') or None
        elif report_type == "Fraud":
            report.fraud_details = request.form.get('fraudDetails') or None
            report.fraud_involved = request.form.get('fraudInvolved') or None
            report.fraud_date = request.form.get('fraudDate') or None
        elif report_type == "Discrimination":
            report.discrimination_details = request.form.get('discriminationDetails') or None
            report.discrimination_basis = request.form.get('discriminationBasis') or None
        elif report_type == "Safety_Violation":
            report.safety_violation_details = request.form.get('safetyViolationDetails') or None
            report.safety_violation_date = request.form.get('safetyViolationDate') or None
        elif report_type == "Conflict_of_Interest":
            report.conflict_details = request.form.get('conflictDetails') or None
            report.conflict_involved = request.form.get('conflictInvolved') or None
        elif report_type == "Bribery":
            report.bribery_details = request.form.get('briberyDetails') or None
            report.bribery_involved = request.form.get('briberyInvolved') or None
        elif report_type == "Environmental_Violation":
            report.environment_violation_details = request.form.get('environmentViolationDetails') or None
            report.environment_violation_date = request.form.get('environmentViolationDate') or None
        elif report_type == "Mismanagement":
            report.mismanagement_details = request.form.get('mismanagementDetails') or None
            report.mismanagement_responsible = request.form.get('mismanagementResponsible') or None
        elif report_type == "Other":
            report.other_details = request.form.get('otherDetails') or None

        # Persist
        db.session.add(report)
        db.session.commit()

        flash('Report submitted successfully', 'success')
        return redirect(url_for('confirmation', access_code=access_code))
    @app.route('/confirmation/<access_code>')
    def confirmation(access_code):
        return render_template('public/confirmation.html', access_code=access_code)
    @app.route('/uploads/<filename>')
    def download_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    @app.route('/dashboard')
    def dashboard():
        if not session.get('user_id'):
            return redirect(url_for('login'))

        # Pull recent reports (limit to 200 for UI responsiveness)
        reports_q = Report.query.order_by(Report.timestamp.desc()).limit(200).all()

        # Summary counts
        new_reports_count = Report.query.filter(Report.status == 'New').count()
        ongoing_investigations_count = Report.query.filter(Report.status == 'Ongoing').count()
        resolved_cases_count = Report.query.filter(Report.status == 'Resolved').count()

        # Prepare lightweight dicts for the front-end (JSON serializable)
        reports_data = []
        status_counts = {}
        type_counts = {}
        monthly_counts = {}
        for r in reports_q:
            status = r.status or 'Unknown'
            rtype = r.report_type or 'Other'
            ts = r.timestamp or datetime.utcnow()
            month_key = ts.strftime('%Y-%m')

            status_counts[status] = status_counts.get(status, 0) + 1
            type_counts[rtype] = type_counts.get(rtype, 0) + 1
            monthly_counts[month_key] = monthly_counts.get(month_key, 0) + 1

            reports_data.append({
                'id': r.id,
                'timestamp': ts.strftime('%Y-%m-%d %H:%M'),
                'status': status,
                'report_type': rtype,
                'report_details': (r.report_details or '').strip(),
                'anonymous_contact': r.anonymous_contact or '',
            })

        # Sort monthly counts chronologically and split into labels/values
        monthly_labels = sorted(monthly_counts.keys())
        monthly_values = [monthly_counts[m] for m in monthly_labels]

        # Unique types for filter dropdown
        unique_types = sorted(type_counts.keys())

        return render_template(
            'dashboard/investigator_dashboard.html',
            new_reports=new_reports_count,
            ongoing_investigations=ongoing_investigations_count,
            resolved_cases=resolved_cases_count,
            reports_data=reports_data,
            status_counts=status_counts,
            type_counts=type_counts,
            monthly_labels=monthly_labels,
            monthly_values=monthly_values,
            unique_types=unique_types,
        )
    

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
                return render_template('public/login.html', error_email=error_email, error_password=error_password)

            # If credentials are valid, store session and redirect
            session['user_id'] = user.id
            session['role'] = (user.role or '').lower()  # normalize for permissions
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or other page

        return render_template('public/login.html')


    @app.route('/privacy-policy')
    def privacy_policy():
        return render_template('public/privacy_policy.html')
    
    @app.route('/logout')
    def logout():
        session.clear()  # Clear the session data
        # Redirect to the login screen after logout
        return redirect(url_for('login'))
    @app.route('/reports', methods=['GET'])
    def reports():
        if not session.get('user_id'):
            return redirect(url_for('login'))

        # Get filters from request arguments
        status = request.args.get('status', '').strip()
        report_type = request.args.get('report_type', '').strip()
        search = request.args.get('search', '').strip()
        assigned_user = request.args.get('assigned_user', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()

        # Query reports with optional filters
        query = Report.query
        if status:
            smap = {'pending': 'New', 'investigating': 'Ongoing', 'completed': 'Resolved'}
            status_norm = smap.get(status, status)
            query = query.filter_by(status=status_norm)
        if report_type:
            rtype_norm = report_type.replace(' ', '_')
            query = query.filter_by(report_type=rtype_norm)
        if search:
            query = query.filter(Report.id == search)  # Search by Report ID
        if assigned_user:
            if assigned_user == 'unassigned':
                query = query.filter(Report.assigned_user_id.is_(None))
            else:
                try:
                    query = query.filter(Report.assigned_user_id == int(assigned_user))
                except ValueError:
                    pass
        if date_from:
            try:
                start_dt = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Report.timestamp >= start_dt)
            except ValueError:
                pass
        if date_to:
            try:
                end_dt = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Report.timestamp < end_dt)
            except ValueError:
                pass

        # Pagination (default 10 per page) and ordering
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        pagination = query.order_by(Report.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        assignable_users = User.query.order_by(User.name.asc()).all()

        return render_template(
            'dashboard/reports.html',
            reports=pagination.items,
            pagination=pagination,
            assignable_users=assignable_users,
        )


    @app.route('/reports/export', methods=['GET'])
    def export_reports():
        if not session.get('user_id'):
            return redirect(url_for('login'))

        # Reuse the same filters as the reports view
        status = request.args.get('status', '').strip()
        report_type = request.args.get('report_type', '').strip()
        search = request.args.get('search', '').strip()
        assigned_user = request.args.get('assigned_user', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()

        query = Report.query
        if status:
            smap = {'pending': 'New', 'investigating': 'Ongoing', 'completed': 'Resolved'}
            status_norm = smap.get(status, status)
            query = query.filter_by(status=status_norm)
        if report_type:
            rtype_norm = report_type.replace(' ', '_')
            query = query.filter_by(report_type=rtype_norm)
        if search:
            query = query.filter(Report.id == search)
        if assigned_user:
            if assigned_user == 'unassigned':
                query = query.filter(Report.assigned_user_id.is_(None))
            else:
                try:
                    query = query.filter(Report.assigned_user_id == int(assigned_user))
                except ValueError:
                    pass
        if date_from:
            try:
                start_dt = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Report.timestamp >= start_dt)
            except ValueError:
                pass
        if date_to:
            try:
                end_dt = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Report.timestamp < end_dt)
            except ValueError:
                pass

        reports = query.order_by(Report.timestamp.desc()).all()

        # Build CSV including ALL columns from the report table, excluding sensitive fields
        output = io.StringIO()
        writer = csv.writer(output)

        columns = [col.name for col in Report.__table__.columns if col.name != 'password_hash']
        writer.writerow(columns)

        for r in reports:
            row = []
            for col in columns:
                val = getattr(r, col)
                if isinstance(val, datetime):
                    val = val.strftime('%Y-%m-%d %H:%M:%S')
                if val is None:
                    val = ''
                row.append(val)
            writer.writerow(row)

        csv_data = output.getvalue()
        resp = make_response(csv_data)
        resp.headers['Content-Type'] = 'text/csv'
        resp.headers['Content-Disposition'] = 'attachment; filename=reports.csv'
        return resp

    @app.route('/my-tasks', methods=['GET'])
    def my_tasks():
        # Require login
        if not session.get('user_id'):
            return redirect(url_for('login'))

        user_id = session.get('user_id')

        # Optional filters
        status = request.args.get('status', '').strip()
        report_type = request.args.get('report_type', '').strip()
        search = request.args.get('search', '').strip()

        query = Report.query.filter(Report.assigned_user_id == user_id)
        if status:
            smap = {'pending': 'New', 'investigating': 'Ongoing', 'completed': 'Resolved'}
            status_norm = smap.get(status, status)
            query = query.filter(Report.status == status_norm)
        if report_type:
            rtype_norm = report_type.replace(' ', '_')
            query = query.filter(Report.report_type == rtype_norm)
        if search:
            query = query.filter(Report.id == search)

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        pagination = query.order_by(Report.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

        return render_template('dashboard/my_tasks.html', reports=pagination.items, pagination=pagination)

    @app.route('/reports/<int:report_id>', methods=['GET', 'POST'])
    def report_detail(report_id):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        from app import db
        report = Report.query.get_or_404(report_id)

        # Build list of assignable users (investigators and admins)
        assignable_users = User.query.filter(User.role.in_(['investigator', 'admin'])).order_by(User.name.asc()).all()
        role = (session.get('role') or '').lower()
        current_user_id = session.get('user_id')
        allowed_to_edit = (role == 'admin') or (role == 'investigator' and report.assigned_user_id == current_user_id)

        if request.method == 'POST':
            action = request.form.get('action', '').strip()

            if action == 'assign':
                assignee_id = request.form.get('assignee_id', '').strip()

                if assignee_id == '':
                    # Unassign and set status to New if not already resolved
                    report.assigned_user_id = None
                    if (report.status or '').lower() != 'resolved':
                        report.status = 'New'
                    db.session.commit()
                    flash('Report unassigned and set to New.', 'success')
                    return redirect(url_for('report_detail', report_id=report.id))

                try:
                    assignee_id_int = int(assignee_id)
                except ValueError:
                    flash('Invalid assignee.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                user = User.query.get(assignee_id_int)
                if not user or user.role not in ('investigator', 'admin'):
                    flash('Assignee must be an investigator or admin.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                report.assigned_user_id = user.id
                # When assigned, mark as Ongoing unless already resolved
                if (report.status or '').lower() != 'resolved':
                    report.status = 'Ongoing'
                db.session.commit()
                flash(f'Report assigned to {user.name} ({user.role}). Status set to Ongoing.', 'success')
                return redirect(url_for('report_detail', report_id=report.id))

            elif action == 'save_investigation':
                # Only admins or the assigned investigator can update investigation fields
                if not allowed_to_edit:
                    flash('You are not authorized to update this report.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                report.investigator_notes = request.form.get('investigator_notes', '')
                report.involved_parties = request.form.get('involved_parties', '')
                report.investigator_conclusion = request.form.get('investigator_conclusion', '')
                report.investigation_updated_at = datetime.utcnow()

                db.session.commit()
                flash('Investigation details saved.', 'success')
                return redirect(url_for('report_detail', report_id=report.id))

            elif action == 'close':
                # Only admins or the assigned investigator can close
                if not allowed_to_edit:
                    flash('You are not authorized to close this report.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                report.status = 'Resolved'
                db.session.commit()
                flash('Report marked as Closed (Resolved).', 'success')
                return redirect(url_for('report_detail', report_id=report.id))

            elif action == 'reopen':
                # Only admins or the assigned investigator can reopen
                if not allowed_to_edit:
                    flash('You are not authorized to reopen this report.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                if report.assigned_user_id:
                    report.status = 'Ongoing'
                else:
                    report.status = 'New'
                db.session.commit()
                flash('Report reopened.', 'success')
                return redirect(url_for('report_detail', report_id=report.id))

            elif action == 'update_overview':
                # Admin or assigned investigator can update key overview fields
                if not allowed_to_edit:
                    flash('You are not authorized to update this report.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                # Validate and apply status
                new_status = (request.form.get('status') or '').strip()
                if new_status in ('New', 'Ongoing', 'Resolved'):
                    report.status = new_status

                # Validate and apply type
                new_type = (request.form.get('report_type') or '').strip()
                valid_types = {
                    'Fraud','Harassment','Discrimination','Safety_Violation','Conflict_of_Interest',
                    'Bribery','Environmental_Violation','Mismanagement','Other'
                }
                if new_type in valid_types:
                    report.report_type = new_type

                # Optional contact
                contact = (request.form.get('anonymous_contact') or '').strip()
                report.anonymous_contact = contact or None

                # Optional timestamp (from datetime-local input)
                ts_str = (request.form.get('timestamp') or '').strip()
                if ts_str:
                    try:
                        report.timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M')
                    except Exception:
                        flash('Invalid timestamp format. Use the date/time picker.', 'warning')

                # Optional access code update (ensure uniqueness)
                new_code = (request.form.get('access_code') or '').strip()
                if new_code and new_code != report.access_code:
                    exists = Report.query.filter(Report.access_code == new_code).first()
                    if exists and exists.id != report.id:
                        flash('Access code already in use. Choose a different one.', 'danger')
                        return redirect(url_for('report_detail', report_id=report.id))
                    report.access_code = new_code

                db.session.commit()
                flash('Overview updated successfully.', 'success')
                return redirect(url_for('report_detail', report_id=report.id))

            elif action == 'apply_suggested_type':
                if not allowed_to_edit:
                    flash('You are not authorized to update this report.', 'danger')
                    return redirect(url_for('report_detail', report_id=report.id))

                suggested = (request.form.get('suggested_type') or '').strip()
                valid_types = {
                    'Fraud','Harassment','Discrimination','Safety_Violation','Conflict_of_Interest',
                    'Bribery','Environmental_Violation','Mismanagement','Other'
                }
                if suggested and suggested in valid_types:
                    report.report_type = suggested
                    db.session.commit()
                    flash(f'Category updated to {suggested}.', 'success')
                else:
                    flash('Invalid suggested category.', 'danger')
                return redirect(url_for('report_detail', report_id=report.id))

            else:
                flash('Unsupported action.', 'danger')
                return redirect(url_for('report_detail', report_id=report.id))

        # ---------- AI/ML helpers: TF‑IDF based suggestions & similarities ----------
        from ml_utils import (
            suggest_report_type_from_reports,
            most_similar_reports,
            fallback_keyword_suggest,
        )

        all_reports = Report.query.all()
        # Similar reports using TF‑IDF cosine
        similar_reports = most_similar_reports(all_reports, report.report_details or '', exclude_id=report.id, top_n=5)

        # Suggested type from centroids; fallback to keyword heuristic if low confidence
        suggested_type, suggested_score = suggest_report_type_from_reports(all_reports, report.report_details or '')
        if not suggested_type or suggested_score < 2:
            # try simple keyword fallback
            k_cat, k_score = fallback_keyword_suggest(report.report_details or '')
            if k_cat:
                suggested_type, suggested_score = k_cat, max(suggested_score, k_score)

        return render_template(
            'dashboard/report_details.html',
            report=report,
            assignable_users=assignable_users,
            allowed_to_edit=allowed_to_edit,
            similar_reports=similar_reports,
            suggested_type=suggested_type,
            suggested_score=suggested_score,
        )
    
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
                return render_template('public/reset_password.html', error="Email not found")

            # Generate password reset token
            token = s.dumps(email, salt='password-reset')

            # Display the reset link directly (for testing without email)
            link = url_for('reset_token', token=token, _external=True)
            return f"Reset link: <a href='{link}'>{link}</a>"

        return render_template('public/reset_password.html')


    @app.route('/reset/<token>', methods=['GET', 'POST'])
    def reset_token(token):
        try:
            email = s.loads(token, salt='password-reset', max_age=3600)  # Token expires after 1 hour
        except SignatureExpired:
            return "The token has expired. Please request a new one.", 400

        if request.method == 'POST':
            new_password = request.form.get('password')

            # Find the user by email and update their password
            user = User.query.filter_by(email=email).first()
            if user and new_password:
                # Store hashed password using model helper
                user.set_password(new_password)
                db.session.commit()
                return "Your password has been reset successfully!"

        return render_template('public/reset_form.html')

















