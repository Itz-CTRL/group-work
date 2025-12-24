from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

# If DATABASE_URL is set (Postgres), use psycopg2; otherwise fall back to sqlite3
DATABASE_URL = os.environ.get('DATABASE_URL')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'shs_portal.db')

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'), static_folder=BASE_DIR)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')

# Hardcoded admin secret (change as needed or set ADMIN_SECRET env var)
ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'adminpass')
# Optional admin host (e.g. admin.example.com). If set, requests to this host
# will be routed to the admin login/dashboard automatically.
ADMIN_HOST = os.environ.get('ADMIN_HOST')


if DATABASE_URL:
    # use psycopg2 for Postgres
    import psycopg2
    import psycopg2.extras


    class DBConnectionWrapper:
        """A small DB connection wrapper that provides execute(), cursor(), commit(), close().
        It translates qmark-style placeholders (?) to %s for psycopg2 execution.
        """
        def __init__(self, conn):
            self._conn = conn

        def cursor(self):
            return self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        def execute(self, sql, params=()):
            # translate qmark placeholders (?) to %s for psycopg2
            sql2 = sql.replace('?', '%s') if params else sql
            cur = self.cursor()
            cur.execute(sql2, params)
            return cur

        def commit(self):
            return self._conn.commit()

        def close(self):
            try:
                self._conn.close()
            except Exception:
                pass

    def get_db_connection():
        # create a new psycopg2 connection and wrap it
        conn = psycopg2.connect(DATABASE_URL)
        return DBConnectionWrapper(conn)

else:
    def get_db_connection():
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            # turn on WAL and foreign keys for better concurrency and integrity
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA foreign_keys=ON;')
        except Exception:
            # If PRAGMA fails for any reason, continue with the connection
            pass
        return conn


def create_table_if_not_exists(conn_obj, sql):
    """Create a table adapting AUTOINCREMENT to Postgres SERIAL when using DATABASE_URL."""
    sql_to_run = sql
    if DATABASE_URL:
        # Replace sqlite-style AUTOINCREMENT with Postgres SERIAL primary key
        sql_to_run = sql_to_run.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        sql_to_run = sql_to_run.replace('AUTOINCREMENT', '')
    try:
        cur_local = conn_obj.cursor()
        cur_local.execute(sql_to_run)
        # commit for safety on connections that require it
        try:
            conn_obj.commit()
        except Exception:
            pass
    except Exception:
        # best-effort: ignore table creation errors
        pass


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # create_table_if_not_exists is defined at module scope and reused below
    # users: id, name, email, password_hash, role
    create_table_if_not_exists(conn, '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT,
        role TEXT CHECK(role IN ('student','admin')) NOT NULL DEFAULT 'student',
        created_at TEXT
    )
    ''')

    # complaints: id, student_email, title, description, category, priority, status, admin_notes, created_at
    create_table_if_not_exists(conn, '''
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT,
        title TEXT,
        description TEXT,
        category TEXT,
        priority TEXT,
        status TEXT DEFAULT 'pending',
        admin_notes TEXT,
        created_at TEXT
    )
    ''')

    # transcripts: id, student_email, type, copies, delivery_method, voucher_code, status, notes, created_at
    create_table_if_not_exists(conn, '''
    CREATE TABLE IF NOT EXISTS transcripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT,
        type TEXT,
        copies INTEGER,
        delivery_method TEXT,
        voucher_code TEXT,
        purpose TEXT,
        addressed_to TEXT,
        status TEXT DEFAULT 'processing',
        notes TEXT,
        deleted_at TEXT,
        created_at TEXT
    )
    ''')

    # notifications: id, user_email, message, created_at, read_flag
    create_table_if_not_exists(conn, '''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        message TEXT,
        created_at TEXT,
        read_flag INTEGER DEFAULT 0
    )
    ''')

    # Ensure users table has optional profile fields (non-breaking ALTER)
    # try each ALTER separately so one failing doesn't stop the other
    try:
        cur.execute('ALTER TABLE users ADD COLUMN house TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN graduation_year INTEGER')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN school TEXT')
    except sqlite3.OperationalError:
        pass
    # Additional optional profile columns for enriched profiles
    try:
        cur.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN current_position TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN company TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN industry TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN location TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN bio TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN linkedin TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN twitter TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN website TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN github TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN show_in_directory INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN available_for_mentorship INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE users ADD COLUMN open_to_networking INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass
    # Non-breaking ALTERs for transcripts: add purpose and addressed_to if missing
    try:
        cur.execute('ALTER TABLE transcripts ADD COLUMN purpose TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE transcripts ADD COLUMN addressed_to TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute('ALTER TABLE transcripts ADD COLUMN deleted_at TEXT')
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


init_db()


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    name = request.form.get('fullName') or request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    # basic validation: ensure fields provided
    if not email or not password:
        flash('Please enter email and password', 'error')
        return redirect(url_for('login'))
    role = request.form.get('role') or 'student'

    if not (name and email and password):
        flash('Please provide name, email and password', 'error')
        return redirect(url_for('signup'))

    school = request.form.get('school')
    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # include optional profile columns (house, school) if present
        house = request.form.get('house') or None
        cur.execute('INSERT INTO users (name, email, password_hash, role, created_at, house, school) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (name, email, password_hash, role, datetime.utcnow().isoformat(), house, school))
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        flash('An account with this email already exists', 'error')
        conn.close()
        return redirect(url_for('signup'))
    finally:
        # ensure connection closed if not already
        try:
            conn.close()
        except:
            pass

    # Auto-login after signup and redirect to appropriate dashboard
    session.clear()
    session['user_id'] = user_id
    session['email'] = email
    session['role'] = role
    session['name'] = name

    flash('Account created and signed in.', 'success')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('student_dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email')
    password = request.form.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))

    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    session['name'] = user['name']
    # expose school to session for immediate use in templates
    try:
        session['school'] = user['school']
    except Exception:
        session['school'] = session.get('school')

    # flash success message
    flash('Logged in successfully.', 'success')

    if user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('student_dashboard'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('name')
        house = request.form.get('house')
        # allow updating graduation year from profile
        graduation_year = request.form.get('graduation_year')
        phone = request.form.get('phone')
        current_position = request.form.get('current_position')
        company = request.form.get('company')
        industry = request.form.get('industry')
        location = request.form.get('location')
        bio = request.form.get('bio')
        linkedin = request.form.get('linkedin')
        twitter = request.form.get('twitter')
        website = request.form.get('website')
        github = request.form.get('github')
        show_in_directory = 1 if request.form.get('show_in_directory') else 0
        available_for_mentorship = 1 if request.form.get('available_for_mentorship') else 0
        open_to_networking = 1 if request.form.get('open_to_networking') else 0
        # update user (school is NOT editable from profile per design)
        cur.execute('''UPDATE users SET name = ?, house = ?, graduation_year = ?, phone = ?, current_position = ?, company = ?, industry = ?, location = ?, bio = ?, linkedin = ?, twitter = ?, website = ?, github = ?, show_in_directory = ?, available_for_mentorship = ?, open_to_networking = ? WHERE email = ?''',
                    (name, house, graduation_year, phone, current_position, company, industry, location, bio, linkedin, twitter, website, github, show_in_directory, available_for_mentorship, open_to_networking, session.get('email')))
        conn.commit()
        # update session so dashboard shows latest values immediately
        session['name'] = name
        session['house'] = house
        # reflect graduation year in session for immediate display
        if graduation_year:
            try:
                session['graduation_year'] = int(graduation_year)
            except Exception:
                session['graduation_year'] = graduation_year
        flash('Profile updated', 'success')
        conn.close()
        # after updating profile, send user back to dashboard so changes are visible
        return redirect(url_for('student_dashboard'))

    row = cur.execute('SELECT id, name, email, role, created_at, house, school, graduation_year, phone, current_position, company, industry, location, bio, linkedin, twitter, website, github, show_in_directory, available_for_mentorship, open_to_networking FROM users WHERE email = ?', (session.get('email'),)).fetchone()
    user = dict(row) if row else None
    # ensure session contains latest profile values for immediate display on dashboard
    if user:
        session['name'] = user.get('name') or session.get('name')
        if user.get('house'):
            session['house'] = user.get('house')
        # keep session['school'] in sync (read-only from signup)
        if user.get('school'):
            session['school'] = user.get('school')
        if user.get('graduation_year'):
            session['graduation_year'] = user.get('graduation_year')
    conn.close()
    return render_template('profile.html', user=user)


@app.route('/settings', methods=['GET'])
def settings():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')


@app.route('/settings/change-password', methods=['POST'])
def change_password():
    if 'email' not in session:
        return redirect(url_for('login'))
    current = request.form.get('current_password')
    newpw = request.form.get('new_password')
    confirm = request.form.get('confirm_password')
    if not (current and newpw and confirm):
        flash('Please fill all password fields', 'error')
        return redirect(url_for('settings'))
    if newpw != confirm:
        flash('New passwords do not match', 'error')
        return redirect(url_for('settings'))

    conn = get_db_connection()
    row = conn.execute('SELECT password_hash FROM users WHERE email = ?', (session.get('email'),)).fetchone()
    if not row or not check_password_hash(row['password_hash'], current):
        conn.close()
        flash('Current password is incorrect', 'error')
        return redirect(url_for('settings'))

    new_hash = generate_password_hash(newpw)
    cur = conn.cursor()
    cur.execute('UPDATE users SET password_hash = ? WHERE email = ?', (new_hash, session.get('email')))
    conn.commit()
    conn.close()
    flash('Password updated successfully', 'success')
    return redirect(url_for('settings'))


@app.route('/directory')
def directory():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('directory.html')


@app.route('/events')
def events():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('events.html')


@app.route('/careers')
def careers():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('careers.html')


@app.route('/donate')
def donate():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('donate.html')


@app.route('/newsletter')
def newsletter():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('newsletter.html')


@app.route('/support')
def support():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('support.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))


@app.route('/password_reset')
def password_reset_page():
    return render_template('password_reset.html')


@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    data = request.get_json() or {}
    email = data.get('email')
    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return jsonify({'exists': bool(user)})


# --- Events API ---
@app.route('/api/events', methods=['GET', 'POST'])
def api_events():
    # GET: list events, POST: create event (admin)
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        if session.get('role') != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        data = request.get_json() or {}
        title = data.get('title')
        description = data.get('description')
        location = data.get('location')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        created_at = datetime.utcnow().isoformat()
        create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, location TEXT, start_time TEXT, end_time TEXT, created_at TEXT)')
        cur.execute('INSERT INTO events (title, description, location, start_time, end_time, created_at) VALUES (?, ?, ?, ?, ?, ?)', (title, description, location, start_time, end_time, created_at))
        conn.commit()
        eid = cur.lastrowid
        conn.close()
        return jsonify({'success': True, 'id': eid})

    # GET: ensure table exists and return events
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, location TEXT, start_time TEXT, end_time TEXT, created_at TEXT)')
    rows = cur.execute('SELECT * FROM events ORDER BY start_time ASC').fetchall()
    events = [dict(r) for r in rows]
    conn.close()
    return jsonify({'events': events})


@app.route('/api/events/<int:event_id>/rsvp', methods=['POST'])
def api_event_rsvp(event_id):
    # allow both logged-in users and anonymous RSVPs
    data = request.get_json() or {}
    name = data.get('name') or session.get('name')
    email = data.get('email') or session.get('email')
    if not (name and email):
        return jsonify({'success': False, 'message': 'Name and email required'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS event_rsvps (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, name TEXT, email TEXT, created_at TEXT)')
    cur.execute('INSERT INTO event_rsvps (event_id, name, email, created_at) VALUES (?, ?, ?, ?)', (event_id, name, email, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# --- Jobs / Careers API ---
@app.route('/api/jobs', methods=['GET', 'POST'])
def api_jobs():
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, company TEXT, location TEXT, type TEXT, experience TEXT, salary TEXT, description TEXT, created_at TEXT)')
    if request.method == 'POST':
        if session.get('role') != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        data = request.get_json() or {}
        cur.execute('INSERT INTO jobs (title, company, location, type, experience, salary, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (
            data.get('title'), data.get('company'), data.get('location'), data.get('type'), data.get('experience'), data.get('salary'), data.get('description'), datetime.utcnow().isoformat()
        ))
        conn.commit()
        jid = cur.lastrowid
        conn.close()
        return jsonify({'success': True, 'id': jid})

    # GET with optional filters
    q = request.args.get('q')
    job_type = request.args.get('type')
    location = request.args.get('location')
    sql = 'SELECT * FROM jobs WHERE 1=1'
    params = []
    if q:
        sql += ' AND (title LIKE ? OR company LIKE ? OR description LIKE ?)'
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%'])
    if job_type:
        sql += ' AND type = ?'
        params.append(job_type)
    if location:
        sql += ' AND location = ?'
        params.append(location)
    sql += ' ORDER BY created_at DESC'
    rows = cur.execute(sql, params).fetchall()
    jobs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'jobs': jobs})


@app.route('/api/jobs/<int:job_id>/apply', methods=['POST'])
def api_job_apply(job_id):
    data = request.get_json() or {}
    name = data.get('name') or session.get('name')
    email = data.get('email') or session.get('email')
    resume = data.get('resume')
    if not (name and email):
        return jsonify({'success': False, 'message': 'Name and email required'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS job_applications (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER, name TEXT, email TEXT, resume TEXT, created_at TEXT)')
    cur.execute('INSERT INTO job_applications (job_id, name, email, resume, created_at) VALUES (?, ?, ?, ?, ?)', (job_id, name, email, resume, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# --- Mentorship API ---
@app.route('/api/mentorship', methods=['GET', 'POST'])
def api_mentorship():
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS mentorships (id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, is_mentor INTEGER, interests TEXT, industries TEXT, bio TEXT, created_at TEXT)')
    if request.method == 'POST':
        data = request.get_json() or {}
        user_email = session.get('email') or data.get('email')
        if not user_email:
            conn.close()
            return jsonify({'success': False, 'message': 'Login or provide email'}), 400
        is_mentor = 1 if data.get('is_mentor') else 0
        interests = data.get('interests')
        industries = data.get('industries')
        bio = data.get('bio')
        cur.execute('INSERT INTO mentorships (user_email, is_mentor, interests, industries, bio, created_at) VALUES (?, ?, ?, ?, ?, ?)', (user_email, is_mentor, interests, industries, bio, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    # GET: return mentors or mentees based on query
    role = request.args.get('role')
    sql = 'SELECT * FROM mentorships'
    params = []
    if role == 'mentor':
        sql += ' WHERE is_mentor = 1'
    elif role == 'mentee':
        sql += ' WHERE is_mentor = 0'
    rows = cur.execute(sql, params).fetchall()
    results = [dict(r) for r in rows]
    conn.close()
    return jsonify({'mentorships': results})


# --- Donations API (placeholder for payment integration) ---
@app.route('/api/donations', methods=['POST', 'GET'])
def api_donations():
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS donations (id INTEGER PRIMARY KEY AUTOINCREMENT, donor_name TEXT, donor_email TEXT, amount REAL, donation_type TEXT, message TEXT, recurring INTEGER, anonymous INTEGER, created_at TEXT)')
    if request.method == 'POST':
        data = request.get_json() or {}
        donor_name = data.get('donor_name') or session.get('name')
        donor_email = data.get('donor_email') or session.get('email')
        amount = float(data.get('amount') or 0)
        donation_type = data.get('donation_type')
        message = data.get('message')
        recurring = 1 if data.get('recurring') else 0
        anonymous = 1 if data.get('anonymous') else 0
        cur.execute('INSERT INTO donations (donor_name, donor_email, amount, donation_type, message, recurring, anonymous, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (donor_name, donor_email, amount, donation_type, message, recurring, anonymous, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    # GET: admin only
    if session.get('role') != 'admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    rows = cur.execute('SELECT * FROM donations ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'donations': [dict(r) for r in rows]})


# --- Newsletter subscription ---
@app.route('/api/newsletter/subscribe', methods=['POST'])
def api_newsletter_subscribe():
    data = request.get_json() or {}
    name = data.get('name') or session.get('name')
    email = data.get('email')
    interests = data.get('interests')
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS newsletter_subscribers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, interests TEXT, created_at TEXT)')
    try:
        cur.execute('INSERT INTO newsletter_subscribers (name, email, interests, created_at) VALUES (?, ?, ?, ?)', (name, email, interests, datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        # already subscribed
        pass
    conn.close()
    return jsonify({'success': True})


# --- Directory search API ---
@app.route('/api/directory/search', methods=['GET'])
def api_directory_search():
    if 'email' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    q = request.args.get('q')
    programme = request.args.get('programme')
    graduation_year = request.args.get('graduation_year')
    industry = request.args.get('industry')
    conn = get_db_connection()
    sql = 'SELECT id, name, email, school, graduation_year, company, current_position, industry, location FROM users WHERE show_in_directory = 1'
    params = []
    if q:
        sql += ' AND (name LIKE ? OR email LIKE ? OR company LIKE ? OR current_position LIKE ?)'
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%'])
    if graduation_year:
        sql += ' AND graduation_year = ?'
        params.append(graduation_year)
    if industry:
        sql += ' AND industry = ?'
        params.append(industry)
    rows = conn.execute(sql + ' ORDER BY name ASC', params).fetchall()
    conn.close()
    return jsonify({'results': [dict(r) for r in rows]})


# --- Admin analytics ---
@app.route('/api/admin/analytics')
def api_admin_analytics():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    stats = {}
    stats['total_users'] = cur.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    # events
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, location TEXT, start_time TEXT, end_time TEXT, created_at TEXT)')
    stats['total_events'] = cur.execute('SELECT COUNT(*) as c FROM events').fetchone()['c']
    # jobs
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, company TEXT, location TEXT, type TEXT, experience TEXT, salary TEXT, description TEXT, created_at TEXT)')
    stats['total_jobs'] = cur.execute('SELECT COUNT(*) as c FROM jobs').fetchone()['c']
    # donations
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS donations (id INTEGER PRIMARY KEY AUTOINCREMENT, donor_name TEXT, donor_email TEXT, amount REAL, donation_type TEXT, message TEXT, recurring INTEGER, anonymous INTEGER, created_at TEXT)')
    stats['total_donations'] = cur.execute('SELECT COUNT(*) as c FROM donations').fetchone()['c']
    stats['donation_sum'] = cur.execute('SELECT COALESCE(SUM(amount),0) as s FROM donations').fetchone()['s']
    # newsletter
    create_table_if_not_exists(conn, 'CREATE TABLE IF NOT EXISTS newsletter_subscribers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, interests TEXT, created_at TEXT)')
    stats['newsletter_subscribers'] = cur.execute('SELECT COUNT(*) as c FROM newsletter_subscribers').fetchone()['c']
    conn.close()
    return jsonify({'success': True, 'stats': stats})


@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    data = request.get_json() or {}
    email = data.get('email')
    new_password = data.get('newPassword')
    if not (email and new_password):
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    # ensure the email exists
    existing = cur.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'success': False, 'message': 'No account found for that email'}), 404

    password_hash = generate_password_hash(new_password)
    cur.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/student/dashboard')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    return render_template('student_dashboard.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    email = request.form.get('adminEmail') or request.form.get('email')
    password = request.form.get('adminPassword') or request.form.get('password')
    # Allow a hardcoded admin password to access admin area. If ADMIN_SECRET
    # is used, create the admin user row if it doesn't exist so session can be set.
    # ADMIN_SECRET branch: create-or-get admin and sign in
    if password == ADMIN_SECRET:
        conn = get_db_connection()
        cur = conn.cursor()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        if not user:
            # create admin user with the secret as password (hashed)
            password_hash = generate_password_hash(password)
            cur.execute('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
                        (email.split('@')[0], email, password_hash, 'admin', datetime.utcnow().isoformat()))
            conn.commit()
            user = cur.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        conn.close()

        # set session and redirect
        session.clear()
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        session['name'] = user['name']
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    # Fallback to normal DB-backed admin authentication
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        flash('Invalid admin credentials', 'error')
        return redirect(url_for('admin_login'))

    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    session['name'] = user['name']
    flash('Logged in successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.before_request
def admin_subdomain_routing():
    """If ADMIN_HOST is set and the request host matches it, route to admin login.
    This enables an admin subdomain (e.g. admin.example.com) to point to the same
    Render service and land administrators on the admin login page.
    """
    try:
        admin_host = ADMIN_HOST
        if not admin_host:
            return None
        # strip port if present
        host = request.host.split(':')[0]
        # if request is already to an admin path, do nothing
        if host == admin_host and not request.path.startswith('/admin'):
            return redirect(url_for('admin_login'))
    except Exception:
        # non-fatal: continue processing
        return None


@app.route('/api/complaints', methods=['POST', 'GET'])
def api_complaints():
    if request.method == 'POST':
        data = request.get_json() or {}
        student_email = data.get('student_email')
        # if the requester is a logged-in student, force student_email to their session email
        if session.get('role') == 'student':
            student_email = session.get('email')
        title = data.get('title')
        description = data.get('description')
        category = data.get('category')
        priority = data.get('priority') or 'medium'
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO complaints (student_email, title, description, category, priority, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (student_email, title, description, category, priority, created_at))
        conn.commit()
        cid = cur.lastrowid
        # notify all admins about the new complaint
        admins = cur.execute("SELECT email FROM users WHERE role = 'admin'").fetchall()
        message = f'New complaint #{cid} by {student_email}: {title}'
        for a in admins:
            cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (a['email'], message, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': cid})

    # GET: list complaints
    email = request.args.get('email')
    conn = get_db_connection()
    # enforce that non-admins can only request their own complaints
    if email:
        if session.get('role') != 'admin' and session.get('email') != email:
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        rows = conn.execute('SELECT * FROM complaints WHERE student_email = ? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        # only admins should fetch all complaints
        if session.get('role') != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        rows = conn.execute('SELECT * FROM complaints ORDER BY created_at DESC').fetchall()
    conn.close()
    complaints = [dict(r) for r in rows]
    return jsonify({'complaints': complaints})


@app.route('/api/complaints/<int:complaint_id>/update', methods=['POST'])
def api_update_complaint(complaint_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    status = data.get('status')
    notes = data.get('notes')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE complaints SET status = ?, admin_notes = ? WHERE id = ?', (status, notes, complaint_id))
    conn.commit()

    # send notification to student
    row = conn.execute('SELECT student_email FROM complaints WHERE id = ?', (complaint_id,)).fetchone()
    if row:
        message = f'Your complaint #{complaint_id} status has been updated to: {status}'
        cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (row['student_email'], message, datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()
    return jsonify({'success': True})


@app.route('/api/transcripts/<int:transcript_id>/update', methods=['POST'])
def api_update_transcript(transcript_id):
    # only admins can update transcript requests
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json() or {}
    status = data.get('status')
    notes = data.get('notes')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE transcripts SET status = ?, notes = ? WHERE id = ?', (status, notes, transcript_id))
    conn.commit()

    # notify the student who requested the transcript
    row = conn.execute('SELECT student_email FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if row:
        # include admin notes in notification when present
        message = f'Your transcript request #{transcript_id} status has been updated to: {status}'
        if notes:
            message += f' — Admin notes: {notes}'
        cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (row['student_email'], message, datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()
    return jsonify({'success': True})


@app.route('/api/transcripts', methods=['POST', 'GET'])
def api_transcripts():
    if request.method == 'POST':
        data = request.get_json() or {}
        student_email = data.get('student_email')
        # if requester is a logged-in student, force student_email to their email
        if session.get('role') == 'student':
            student_email = session.get('email')
        ttype = data.get('type')
        copies = int(data.get('copies') or 1)
        delivery = data.get('delivery_method')
        voucher = data.get('voucher_code')
        notes = data.get('notes')
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO transcripts (student_email, type, copies, delivery_method, voucher_code, purpose, addressed_to, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (student_email, ttype, copies, delivery, voucher, data.get('purpose'), data.get('addressed_to'), notes, created_at))
        conn.commit()
        tid = cur.lastrowid
        # notify admins about new transcript/testimonial request (include purpose/addressed_to)
        try:
            admins = cur.execute("SELECT email FROM users WHERE role = 'admin'").fetchall()
            notify_msg = f'New {ttype} request #{tid} by {student_email}'
            if data.get('purpose'):
                notify_msg += f" — Purpose: {data.get('purpose')}"
            if data.get('addressed_to'):
                notify_msg += f" — Addressed To: {data.get('addressed_to')}"
            for a in admins:
                cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (a['email'], notify_msg, datetime.utcnow().isoformat()))
            conn.commit()
        except Exception:
            pass
        conn.close()
        return jsonify({'success': True, 'id': tid})

    conn = get_db_connection()
    email = request.args.get('email')
    # enforce that non-admins can only fetch their own transcripts
    include_trashed = request.args.get('include_trashed') == 'true'
    if email:
        if session.get('role') != 'admin' and session.get('email') != email:
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        # students should not see trashed items by default
        rows = conn.execute('SELECT * FROM transcripts WHERE student_email = ? AND deleted_at IS NULL ORDER BY created_at DESC', (email,)).fetchall()
    else:
        # only admins can fetch all transcripts; allow optional inclusion of trashed items
        if session.get('role') != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        if include_trashed:
            rows = conn.execute('SELECT * FROM transcripts ORDER BY created_at DESC').fetchall()
        else:
            rows = conn.execute('SELECT * FROM transcripts WHERE deleted_at IS NULL ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'transcripts': [dict(r) for r in rows]})


@app.route('/api/transcripts/<int:transcript_id>', methods=['DELETE'])
def api_delete_transcript(transcript_id):
    # allow admin or the student who created the request to delete it
    conn = get_db_connection()
    row = conn.execute('SELECT student_email FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404

    # authorization
    if session.get('role') != 'admin' and session.get('email') != row['student_email']:
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # soft-delete: mark deleted_at and set status to 'deleted'
    cur = conn.cursor()
    deleted_at = datetime.utcnow().isoformat()
    cur.execute('UPDATE transcripts SET deleted_at = ?, status = ? WHERE id = ?', (deleted_at, 'deleted', transcript_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'deleted_at': deleted_at})


@app.route('/api/transcripts/<int:transcript_id>/restore', methods=['POST'])
def api_restore_transcript(transcript_id):
    # allow admin or the student who created the request to restore it
    conn = get_db_connection()
    row = conn.execute('SELECT student_email, deleted_at FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404
    if session.get('role') != 'admin' and session.get('email') != row['student_email']:
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    cur = conn.cursor()
    cur.execute('UPDATE transcripts SET deleted_at = NULL, status = ? WHERE id = ?', ('processing', transcript_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/admin/cleanup_trash', methods=['POST'])
def api_cleanup_trash():
    # admin-only endpoint to permanently remove trashed items older than 30 days
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    threshold = (datetime.utcnow() - timedelta(days=30)).isoformat()
    cur.execute('DELETE FROM transcripts WHERE deleted_at IS NOT NULL AND deleted_at <= ?', (threshold,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'deleted_rows': deleted})


@app.route('/api/admin/permanent_delete/<int:transcript_id>', methods=['POST'])
def api_permanent_delete(transcript_id):
    # permanently delete a trashed transcript/testimonial (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    # Only allow permanent delete if item exists
    row = conn.execute('SELECT id FROM transcripts WHERE id = ?', (transcript_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404
    cur.execute('DELETE FROM transcripts WHERE id = ?', (transcript_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return jsonify({'success': True, 'deleted_rows': deleted})


@app.route('/api/admin/permanent_delete_bulk', methods=['POST'])
def api_permanent_delete_bulk():
    # permanently delete multiple trashed transcripts (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or len(ids) == 0:
        return jsonify({'success': False, 'message': 'No ids provided'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    placeholders = ','.join('?' for _ in ids)
    cur.execute(f'DELETE FROM transcripts WHERE id IN ({placeholders})', ids)
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'deleted_rows': deleted})


@app.route('/api/admin/restore_bulk', methods=['POST'])
def api_restore_bulk():
    # restore multiple trashed transcripts (admin only)
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or len(ids) == 0:
        return jsonify({'success': False, 'message': 'No ids provided'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    placeholders = ','.join('?' for _ in ids)
    cur.execute(f'UPDATE transcripts SET deleted_at = NULL, status = ? WHERE id IN ({placeholders})', tuple(['processing'] + ids))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'updated_rows': updated})


@app.route('/api/notifications/mark_read', methods=['POST'])
def api_notifications_mark_read():
    data = request.get_json() or {}
    email = data.get('email')
    ids = data.get('ids')
    mark_all = data.get('all')

    # only allow marking one's own notifications as read unless admin
    if session.get('email') != email and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    if ids and isinstance(ids, list) and len(ids) > 0:
        placeholders = ','.join('?' for _ in ids)
        params = [*ids, email]
        cur.execute(f'UPDATE notifications SET read_flag = 1 WHERE id IN ({placeholders}) AND user_email = ?', params)
    elif mark_all:
        cur.execute('UPDATE notifications SET read_flag = 1 WHERE user_email = ?', (email,))
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'No ids or all flag provided'}), 400

    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
def api_delete_notification(notification_id):
    # allow user to delete their own notification or admin to delete any
    user_email = session.get('email')
    role = session.get('role')
    if not user_email:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    row = conn.execute('SELECT user_email FROM notifications WHERE id = ?', (notification_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404

    if role != 'admin' and row['user_email'] != user_email:
        conn.close()
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    cur = conn.cursor()
    cur.execute('DELETE FROM notifications WHERE id = ?', (notification_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/clear_read', methods=['POST'])
def api_clear_read_notifications():
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Missing email'}), 400

    # only allow clearing one's own notifications unless admin
    if session.get('email') != email and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM notifications WHERE user_email = ? AND read_flag = 1', (email,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications', methods=['POST', 'GET'])
def api_notifications():
    if request.method == 'POST':
        data = request.get_json() or {}
        recipient = data.get('recipient')  # 'all' or specific email
        message = data.get('message')
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        if recipient == 'all':
            # send to all students
            users = conn.execute("SELECT email FROM users WHERE role='student'").fetchall()
            for u in users:
                cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (u['email'], message, created_at))
            # also add a copy for the sender (if logged in) so they can see the notification they sent
            sender_email = session.get('email')
            if sender_email:
                cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (sender_email, message, created_at))
        else:
            cur.execute('INSERT INTO notifications (user_email, message, created_at) VALUES (?, ?, ?)', (recipient, message, created_at))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    # GET
    email = request.args.get('email')
    conn = get_db_connection()
    if email:
        # non-admins may only request their own notifications
        if session.get('role') != 'admin' and session.get('email') != email:
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        rows = conn.execute('SELECT * FROM notifications WHERE user_email = ? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        # only admins may fetch all notifications
        if session.get('role') != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        rows = conn.execute('SELECT * FROM notifications ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'notifications': [dict(r) for r in rows]})


@app.route('/api/users', methods=['GET'])
def api_users():
    # Only admins should retrieve full user lists
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    conn = get_db_connection()
    rows = conn.execute('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    users = [dict(r) for r in rows]
    return jsonify({'users': users})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    # only admins can delete users
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # prevent deleting yourself
    if session.get('user_id') == user_id:
        return jsonify({'success': False, 'message': "You can't delete your own account"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
