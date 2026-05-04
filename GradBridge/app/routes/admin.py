from flask import Blueprint, request, session, jsonify, redirect, url_for, render_template, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from ..models import db, User, Complaint, Transcript, Notification

admin_bp = Blueprint('admin', __name__, template_folder='../templates/admin')

@admin_bp.before_request
def admin_subdomain_routing():
    """If ADMIN_HOST is set and the request host matches it, route to admin login.
    This enables an admin subdomain (e.g. admin.example.com) to point to the same
    Render service and land administrators on the admin login page.
    """
    try:
        admin_host = current_app.config.get('ADMIN_HOST')
        if not admin_host:
            return None
        # strip port if present
        host = request.host.split(':')[0]
        # if request is already to an admin path, do nothing
        if host == admin_host and not request.path.startswith('/admin'):
            return redirect(url_for('admin.admin_login'))
    except Exception:
        # non-fatal: continue processing
        return None

@admin_bp.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    return render_template('admin_dashboard.html')

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    email = (request.form.get('adminEmail') or request.form.get('email') or '').strip().lower()
    password = request.form.get('adminPassword') or request.form.get('password') or ''
    if not email or not password:
        flash('Please enter both admin email and password.', 'error')
        return redirect(url_for('admin.admin_login'))

    ADMIN_SECRET = current_app.config.get('ADMIN_SECRET', 'adminpass')
    # Allow a hardcoded admin password to access admin area. If ADMIN_SECRET
    # is used, create the admin user row if it doesn't exist so session can be set.
    # ADMIN_SECRET branch: create-or-get admin and sign in
    if password == ADMIN_SECRET:
        user = User.query.filter_by(email=email, role='admin').first()
        if not user:
            # create admin user with the secret as password (hashed)
            password_hash = generate_password_hash(password)
            user = User(name=email.split('@')[0], email=email, password_hash=password_hash, role='admin', created_at=datetime.utcnow().isoformat())
            db.session.add(user)
            db.session.commit()
        # set session and redirect
        session.clear()
        session['user_id'] = user.id
        session['email'] = user.email
        session['role'] = user.role
        session['name'] = user.name
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin.admin_dashboard'))

    # Fallback to normal DB-backed admin authentication
    user = User.query.filter_by(email=email, role='admin').first()
    if not user or not check_password_hash(user.password_hash, password):
        flash('Invalid admin credentials', 'error')
        return redirect(url_for('admin.admin_login'))

    session.clear()
    session['user_id'] = user.id
    session['email'] = user.email
    session['role'] = user.role
    session['name'] = user.name
    flash('Logged in successfully.', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/api/admin/cleanup_trash', methods=['POST'])
def api_cleanup_trash():
    # admin-only endpoint to permanently remove trashed items older than 30 days
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    threshold = (datetime.utcnow() - timedelta(days=30)).isoformat()
    deleted = Transcript.query.filter(Transcript.deleted_at.isnot(None), Transcript.deleted_at <= threshold).delete()
    db.session.commit()
    return jsonify({'success': True, 'deleted_rows': deleted})

@admin_bp.route('/api/admin/permanent_delete/<int:transcript_id>', methods=['POST'])
def api_permanent_delete(transcript_id):
    # permanently delete a trashed transcript/testimonial (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    transcript = Transcript.query.get(transcript_id)
    if not transcript:
        return jsonify({'success': False, 'message': 'Not found'}), 404
    db.session.delete(transcript)
    db.session.commit()
    return jsonify({'success': True, 'deleted_rows': 1})

@admin_bp.route('/api/admin/permanent_delete_bulk', methods=['POST'])
def api_permanent_delete_bulk():
    # permanently delete multiple trashed transcripts (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or len(ids) == 0:
        return jsonify({'success': False, 'message': 'No ids provided'}), 400
    deleted = Transcript.query.filter(Transcript.id.in_(ids)).delete()
    db.session.commit()
    return jsonify({'success': True, 'deleted_rows': deleted})

@admin_bp.route('/api/admin/restore_bulk', methods=['POST'])
def api_restore_bulk():
    # restore multiple trashed transcripts (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or len(ids) == 0:
        return jsonify({'success': False, 'message': 'No ids provided'}), 400
    updated = Transcript.query.filter(Transcript.id.in_(ids)).update({'deleted_at': None, 'status': 'processing'})
    db.session.commit()
    return jsonify({'success': True, 'updated_rows': updated})

@admin_bp.route('/api/notifications/mark_read', methods=['POST'])
def api_notifications_mark_read():
    data = request.get_json() or {}
    email = data.get('email')
    ids = data.get('ids')
    mark_all = data.get('all')

    # only allow marking one's own notifications as read unless admin
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


@admin_bp.route('/api/users', methods=['GET'])
def api_list_users():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    users = User.query.order_by(User.id.desc()).all()
    return jsonify({'success': True, 'users': [
        {
            'id': u.id,
            'name': u.name,
            'email': u.email,
            'role': u.role,
            'graduation_year': u.graduation_year,
            'school': u.school,
            'alum_id': None,
            'created_at': u.created_at or '',
        } for u in users
    ]})


@admin_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    # only admins can delete users
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'Not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})


@admin_bp.route('/api/complaints/<int:complaint_id>/update', methods=['POST'])
def api_update_complaint(complaint_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    complaint = Complaint.query.get(complaint_id)
    if not complaint:
        return jsonify({'success': False, 'message': 'Not found'}), 404
    data = request.get_json() or {}
    old_status = complaint.status
    complaint.status = data.get('status', complaint.status)
    complaint.admin_notes = data.get('notes', complaint.admin_notes)
    db.session.commit()
    if complaint.student_email and old_status != complaint.status:
        notif = Notification(
            user_email=complaint.student_email,
            message=f'Your complaint "{complaint.title}" status has been updated to: {complaint.status}.' ,
            created_at=datetime.utcnow().isoformat(),
            read_flag=False,
        )
        db.session.add(notif)
        db.session.commit()
    return jsonify({'success': True})


@admin_bp.route('/api/transcripts/<int:transcript_id>/update', methods=['POST'])
def api_update_transcript(transcript_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    transcript = Transcript.query.get(transcript_id)
    if not transcript:
        return jsonify({'success': False, 'message': 'Not found'}), 404
    data = request.get_json() or {}
    old_status = transcript.status
    transcript.status = data.get('status', transcript.status)
    transcript.notes = data.get('notes', transcript.notes)
    db.session.commit()
    if transcript.student_email and old_status != transcript.status:
        notif = Notification(
            user_email=transcript.student_email,
            message=f'Your {transcript.type} request status has been updated to: {transcript.status}.',
            created_at=datetime.utcnow().isoformat(),
            read_flag=False,
        )
        db.session.add(notif)
        db.session.commit()
    return jsonify({'success': True})


@admin_bp.route('/api/transcripts/<int:transcript_id>/restore', methods=['POST'])
def api_restore_transcript(transcript_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    transcript = Transcript.query.get(transcript_id)
    if not transcript:
        return jsonify({'success': False, 'message': 'Not found'}), 404
    transcript.deleted_at = None
    transcript.status = 'processing'
    db.session.commit()
    return jsonify({'success': True})


@admin_bp.route('/api/notifications', methods=['POST'])
def api_send_notification():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    message = data.get('message', '').strip()
    recipient = data.get('recipient', '')
    if not message:
        return jsonify({'success': False, 'message': 'Message required'}), 400
    now = datetime.utcnow().isoformat()
    if recipient == 'all':
        students = User.query.filter_by(role='student').all()
        for u in students:
            db.session.add(Notification(
                user_email=u.email,
                message=message,
                created_at=now,
                read_flag=False,
            ))
    else:
        db.session.add(Notification(
            user_email=recipient,
            message=message,
            created_at=now,
            read_flag=False,
        ))
    db.session.commit()
    return jsonify({'success': True})