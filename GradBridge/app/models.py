import os
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def configure_db(app):
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL:
        # For Postgres, ensure it's in the correct format for SQLAlchemy
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://')
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    else:
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Up to Alumini-Portal
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "data", "shs_portal.db")}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

def init_db():
    with db.session.begin():
        db.create_all()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password_hash = db.Column(db.String)
    role = db.Column(db.String, default='student')
    created_at = db.Column(db.String)
    house = db.Column(db.String)
    graduation_year = db.Column(db.Integer)
    school = db.Column(db.String)
    phone = db.Column(db.String)
    current_position = db.Column(db.String)
    company = db.Column(db.String)
    industry = db.Column(db.String)
    location = db.Column(db.String)
    bio = db.Column(db.Text)
    linkedin = db.Column(db.String)
    twitter = db.Column(db.String)
    website = db.Column(db.String)
    github = db.Column(db.String)
    show_in_directory = db.Column(db.Boolean, default=True)
    available_for_mentorship = db.Column(db.Boolean, default=False)
    open_to_networking = db.Column(db.Boolean, default=True)
    course = db.Column(db.String)
    education_type = db.Column(db.String)
    __table_args__ = (
        db.CheckConstraint("role IN ('student', 'admin')"),
        db.CheckConstraint("education_type IN ('university', 'shs')"),
    )

class Complaint(db.Model):
    __tablename__ = 'complaints'
    id = db.Column(db.Integer, primary_key=True)
    student_email = db.Column(db.String)
    title = db.Column(db.String)
    description = db.Column(db.Text)
    category = db.Column(db.String)
    priority = db.Column(db.String)
    status = db.Column(db.String, default='pending')
    admin_notes = db.Column(db.Text)
    created_at = db.Column(db.String)

class Transcript(db.Model):
    __tablename__ = 'transcripts'
    id = db.Column(db.Integer, primary_key=True)
    student_email = db.Column(db.String)
    type = db.Column(db.String)
    copies = db.Column(db.Integer)
    delivery_method = db.Column(db.String)
    voucher_code = db.Column(db.String)
    purpose = db.Column(db.String)
    addressed_to = db.Column(db.String)
    status = db.Column(db.String, default='processing')
    notes = db.Column(db.Text)
    deleted_at = db.Column(db.String)
    created_at = db.Column(db.String)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String)
    message = db.Column(db.Text)
    created_at = db.Column(db.String)
    read_flag = db.Column(db.Boolean, default=False)

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    description = db.Column(db.Text)
    location = db.Column(db.String)
    start_time = db.Column(db.String)
    end_time = db.Column(db.String)
    created_at = db.Column(db.String)

class EventRsvp(db.Model):
    __tablename__ = 'event_rsvps'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer)
    name = db.Column(db.String)
    email = db.Column(db.String)
    created_at = db.Column(db.String)

class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    company = db.Column(db.String)
    location = db.Column(db.String)
    type = db.Column(db.String)
    experience = db.Column(db.String)
    salary = db.Column(db.String)
    description = db.Column(db.Text)
    created_at = db.Column(db.String)

class JobApplication(db.Model):
    __tablename__ = 'job_applications'
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer)
    name = db.Column(db.String)
    email = db.Column(db.String)
    resume = db.Column(db.Text)
    created_at = db.Column(db.String)

class Mentorship(db.Model):
    __tablename__ = 'mentorships'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String)
    is_mentor = db.Column(db.Boolean)
    interests = db.Column(db.Text)
    industries = db.Column(db.Text)
    bio = db.Column(db.Text)
    created_at = db.Column(db.String)

class Donation(db.Model):
    __tablename__ = 'donations'
    id = db.Column(db.Integer, primary_key=True)
    donor_name = db.Column(db.String)
    donor_email = db.Column(db.String)
    amount = db.Column(db.Float)
    donation_type = db.Column(db.String)
    message = db.Column(db.Text)
    recurring = db.Column(db.Boolean)
    anonymous = db.Column(db.Boolean)
    created_at = db.Column(db.String)

class NewsletterSubscriber(db.Model):
    __tablename__ = 'newsletter_subscribers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    interests = db.Column(db.Text)
    created_at = db.Column(db.String)