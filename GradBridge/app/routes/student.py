from flask import request, session, jsonify, redirect, url_for, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from ..models import (
    db, User, Complaint, Transcript, Notification,
    Event, Job, Donation, NewsletterSubscriber,
)

_CURRENT_YEAR = datetime.utcnow().year


# ─── Auth guard ────────────────────────────────────────────────────────────────

def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ─── Route registration ────────────────────────────────────────────────────────

def register_routes(app):

    # ── Context processor: inject current_year into every template ────────────
    @app.context_processor
    def inject_globals():
        return {'current_year': _CURRENT_YEAR}

    # ── Home redirect ──────────────────────────────────────────────────────────

    @app.route('/')
    def index():
        if session.get('user_id') and session.get('role') == 'student':
            return redirect(url_for('student_dashboard'))
        return redirect(url_for('login'))

    # ─── AUTH ──────────────────────────────────────────────────────────────────

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('user_id') and session.get('role') == 'student':
            return redirect(url_for('student_dashboard'))

        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            user = User.query.filter_by(email=email, role='student').first()
            if not user or not check_password_hash(user.password_hash, password):
                flash('Invalid email or password.', 'error')
                return redirect(url_for('login'))

            session.clear()
            session['user_id'] = user.id
            session['email'] = user.email
            session['name'] = user.name
            session['role'] = user.role
            session['school'] = user.school or ''
            session['graduation_year'] = user.graduation_year or ''
            session['course'] = user.course or ''
            flash('Welcome back, {}!'.format(user.name), 'success')
            return redirect(url_for('student_dashboard'))

        return render_template('student/login.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            name = request.form.get('fullName', '').strip()
            email = request.form.get('email', '').strip().lower()
            school = request.form.get('school', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirmPassword', '')

            if not name or not email or not password:
                flash('Please fill in all required fields.', 'error')
                return redirect(url_for('signup'))
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('signup'))
            if len(password) < 6:
                flash('Password must be at least 6 characters.', 'error')
                return redirect(url_for('signup'))
            if User.query.filter_by(email=email).first():
                flash('An account with this email already exists.', 'error')
                return redirect(url_for('signup'))

            user = User(
                name=name,
                email=email,
                school=school,
                password_hash=generate_password_hash(password),
                role='student',
                created_at=datetime.utcnow().isoformat(),
            )
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('student/signup.html')

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))

    @app.route('/password-reset')
    def password_reset_page():
        return render_template('student/password_reset.html')

    # ─── STUDENT PAGES ─────────────────────────────────────────────────────────

    @app.route('/dashboard')
    @_login_required
    def student_dashboard():
        return render_template('student/student_dashboard.html')

    @app.route('/profile', methods=['GET', 'POST'])
    @_login_required
    def profile():
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))

        if request.method == 'POST':
            user.name = request.form.get('name', user.name).strip() or user.name
            user.phone = request.form.get('phone', '').strip()
            user.house = request.form.get('house', '').strip()
            user.course = request.form.get('course', '').strip()
            user.current_position = request.form.get('current_position', '').strip()
            user.company = request.form.get('company', '').strip()
            user.industry = request.form.get('industry', '').strip()
            user.location = request.form.get('location', '').strip()
            user.bio = request.form.get('bio', '').strip()
            user.linkedin = request.form.get('linkedin', '').strip()
            user.twitter = request.form.get('twitter', '').strip()
            user.website = request.form.get('website', '').strip()
            user.github = request.form.get('github', '').strip()
            user.show_in_directory = 'show_in_directory' in request.form
            user.available_for_mentorship = 'available_for_mentorship' in request.form
            user.open_to_networking = 'open_to_networking' in request.form
            grad_year = request.form.get('graduation_year', '').strip()
            if grad_year and grad_year.isdigit():
                user.graduation_year = int(grad_year)
            db.session.commit()
            # keep session in sync
            session['name'] = user.name
            session['course'] = user.course or ''
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        return render_template('student/profile.html', user=user)

    @app.route('/settings')
    @_login_required
    def settings():
        return render_template('student/settings.html')

    @app.route('/change-password', methods=['POST'], endpoint='change_password')
    @_login_required
    def change_password():
        user = User.query.get(session['user_id'])
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not check_password_hash(user.password_hash, current_pw):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('settings'))
        if len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return redirect(url_for('settings'))
        if new_pw != confirm_pw:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('settings'))

        user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('settings'))

    @app.route('/careers')
    @_login_required
    def careers():
        jobs = Job.query.order_by(Job.created_at.desc()).all()
        return render_template('student/careers.html', jobs=jobs)

    @app.route('/directory')
    @_login_required
    def directory():
        alumni = User.query.filter_by(role='student', show_in_directory=True).all()
        return render_template('student/directory.html', alumni=alumni)

    @app.route('/donate')
    @_login_required
    def donate():
        return render_template('student/donate.html')

    @app.route('/events')
    @_login_required
    def events():
        events_list = Event.query.order_by(Event.start_time.asc()).all()
        return render_template('student/events.html', events=events_list)

    @app.route('/newsletter')
    @_login_required
    def newsletter():
        return render_template('student/newsletter.html')

    @app.route('/support')
    @_login_required
    def support():
        return render_template('student/support.html')

    # ─── API: COMPLAINTS ───────────────────────────────────────────────────────

    @app.route('/api/complaints', methods=['POST'])
    def api_create_complaint():
        data = request.get_json() or {}
        email = data.get('student_email') or session.get('email')
        if not email:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401
        complaint = Complaint(
            student_email=email,
            title=data.get('title', ''),
            description=data.get('description', ''),
            category=data.get('category', ''),
            priority=data.get('priority', 'medium'),
            status='pending',
            created_at=datetime.utcnow().isoformat(),
        )
        db.session.add(complaint)
        db.session.commit()
        return jsonify({'success': True, 'id': complaint.id})

    @app.route('/api/complaints', methods=['GET'])
    def api_get_complaints():
        is_admin = session.get('role') == 'admin'
        if is_admin:
            complaints = Complaint.query.order_by(Complaint.id.desc()).all()
        else:
            email = request.args.get('email') or session.get('email')
            if not email:
                return jsonify({'success': False, 'message': 'Email required'}), 400
            if session.get('email') != email:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            complaints = Complaint.query.filter_by(student_email=email).order_by(Complaint.id.desc()).all()
        return jsonify({'success': True, 'complaints': [
            {
                'id': c.id, 'title': c.title, 'description': c.description,
                'category': c.category, 'priority': c.priority,
                'status': c.status, 'admin_notes': c.admin_notes,
                'student_email': c.student_email,
                'created_at': c.created_at,
            } for c in complaints
        ]})

    # ─── API: TRANSCRIPTS ──────────────────────────────────────────────────────

    @app.route('/api/transcripts', methods=['POST'])
    def api_create_transcript():
        data = request.get_json() or {}
        email = data.get('student_email') or session.get('email')
        if not email:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401
        try:
            copies = int(data.get('copies') or 1)
        except (TypeError, ValueError):
            copies = 1
        transcript = Transcript(
            student_email=email,
            type=data.get('type', 'official'),
            copies=copies,
            delivery_method=data.get('delivery_method', ''),
            voucher_code=data.get('voucher_code', ''),
            purpose=data.get('purpose', ''),
            addressed_to=data.get('addressed_to', ''),
            notes=data.get('notes', ''),
            status='processing',
            created_at=datetime.utcnow().isoformat(),
        )
        db.session.add(transcript)
        db.session.commit()
        return jsonify({'success': True, 'id': transcript.id})

    @app.route('/api/transcripts', methods=['GET'])
    def api_get_transcripts():
        is_admin = session.get('role') == 'admin'
        include_trashed = request.args.get('include_trashed') == 'true'
        if is_admin:
            q = Transcript.query
            if not include_trashed:
                q = q.filter(Transcript.deleted_at.is_(None))
            transcripts = q.order_by(Transcript.id.desc()).all()
        else:
            email = request.args.get('email') or session.get('email')
            if not email:
                return jsonify({'success': False, 'message': 'Email required'}), 400
            if session.get('email') != email:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            transcripts = Transcript.query.filter(
                Transcript.student_email == email,
                Transcript.deleted_at.is_(None),
            ).order_by(Transcript.id.desc()).all()
        return jsonify({'success': True, 'transcripts': [
            {
                'id': t.id, 'type': t.type, 'copies': t.copies,
                'delivery_method': t.delivery_method, 'voucher_code': t.voucher_code,
                'purpose': t.purpose, 'addressed_to': t.addressed_to,
                'notes': t.notes, 'status': t.status,
                'student_email': t.student_email,
                'deleted_at': t.deleted_at,
                'created_at': t.created_at,
            } for t in transcripts
        ]})

    @app.route('/api/transcripts/<int:transcript_id>', methods=['DELETE'])
    def api_delete_transcript(transcript_id):
        transcript = Transcript.query.get(transcript_id)
        if not transcript:
            return jsonify({'success': False, 'message': 'Not found'}), 404
        if session.get('role') != 'admin' and transcript.student_email != session.get('email'):
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        # soft-delete so admin trash still works
        transcript.deleted_at = datetime.utcnow().isoformat()
        db.session.commit()
        return jsonify({'success': True})

    # ─── API: NOTIFICATIONS ────────────────────────────────────────────────────

    @app.route('/api/notifications', methods=['GET'])
    def api_get_notifications():
        email = request.args.get('email') or session.get('email')
        if not email:
            return jsonify({'success': False, 'message': 'Email required'}), 400
        if session.get('role') != 'admin' and session.get('email') != email:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        notifications = Notification.query.filter_by(user_email=email).order_by(Notification.id.desc()).all()
        return jsonify({'success': True, 'notifications': [
            {
                'id': n.id, 'message': n.message,
                'created_at': n.created_at, 'read_flag': n.read_flag,
            } for n in notifications
        ]})

    @app.route('/api/notifications/mark_read', methods=['POST'])
    def api_notifications_mark_read():
        data = request.get_json() or {}
        email = data.get('email')
        ids = data.get('ids')
        mark_all = data.get('all')

        if session.get('email') != email and session.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403

        if ids and isinstance(ids, list) and len(ids) > 0:
            Notification.query.filter(
                Notification.id.in_(ids),
                Notification.user_email == email,
            ).update({'read_flag': True}, synchronize_session=False)
        elif mark_all:
            Notification.query.filter_by(user_email=email).update({'read_flag': True})
        else:
            return jsonify({'success': False, 'message': 'No ids or all flag provided'}), 400

        db.session.commit()
        return jsonify({'success': True})

    @app.route('/api/notifications/clear_read', methods=['POST'])
    def api_notifications_clear_read():
        data = request.get_json() or {}
        email = data.get('email') or session.get('email')
        if not email:
            return jsonify({'success': False, 'message': 'Email required'}), 400
        if session.get('email') != email and session.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        deleted = Notification.query.filter_by(user_email=email, read_flag=True).delete()
        db.session.commit()
        return jsonify({'success': True, 'deleted': deleted})

    @app.route('/api/notifications/<int:notif_id>', methods=['DELETE'])
    def api_delete_notification(notif_id):
        notif = Notification.query.get(notif_id)
        if not notif:
            return jsonify({'success': False, 'message': 'Not found'}), 404
        if session.get('role') != 'admin' and notif.user_email != session.get('email'):
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        db.session.delete(notif)
        db.session.commit()
        return jsonify({'success': True})

    # ─── API: PASSWORD RESET ───────────────────────────────────────────────────

    @app.route('/api/check-email', methods=['POST'])
    def api_check_email():
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        return jsonify({'exists': bool(user)})

    @app.route('/api/reset-password', methods=['POST'])
    def api_reset_password():
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        new_password = data.get('newPassword', '')
        if not email or not new_password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password too short'}), 400
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'success': True})

    # ─── API: DONATIONS ────────────────────────────────────────────────────────

    @app.route('/api/donations', methods=['POST'])
    def api_create_donation():
        data = request.get_json() or {}
        try:
            amount = float(data.get('amount') or 0)
        except (TypeError, ValueError):
            amount = 0.0
        donation = Donation(
            donor_name=data.get('donor_name', ''),
            donor_email=data.get('donor_email', ''),
            amount=amount,
            donation_type=data.get('donation_type', ''),
            message=data.get('message', ''),
            recurring=bool(data.get('recurring')),
            anonymous=bool(data.get('anonymous')),
            created_at=datetime.utcnow().isoformat(),
        )
        db.session.add(donation)
        db.session.commit()
        return jsonify({'success': True, 'id': donation.id})

    # ─── API: NEWSLETTER ───────────────────────────────────────────────────────

    @app.route('/api/newsletter/subscribe', methods=['POST'])
    def api_newsletter_subscribe():
        data = request.get_json() or {}
        email = data.get('email', '').strip().lower()
        name = data.get('name', '').strip()
        if not email:
            return jsonify({'success': False, 'message': 'Email required'}), 400
        if NewsletterSubscriber.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Already subscribed'}), 409
        interests_raw = data.get('interests', [])
        interests = ','.join(interests_raw) if isinstance(interests_raw, list) else ''
        sub = NewsletterSubscriber(
            name=name,
            email=email,
            interests=interests,
            created_at=datetime.utcnow().isoformat(),
        )
        db.session.add(sub)
        db.session.commit()
        return jsonify({'success': True})




