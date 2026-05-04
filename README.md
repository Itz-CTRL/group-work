# GradBridge - Alumni Portal

A Flask-based web application for managing alumni networks, transcripts, events, and community engagement.

## Features

- **Student Authentication** - User registration and login
- **Admin Portal** - Manage users, complaints, and transcripts
- **Profiles & Directory** - Alumni profiles with searchable directory
- **Careers** - Job board for alumni opportunities
- **Events & Newsletter** - Community events and newsletter subscriptions
- **Donations** - Support system for alumni contributions
- **Transcripts** - Request and manage academic transcripts

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- SQLite (included with Python)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Alumini-Portal
   ```

2. **Create a virtual environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   - Copy the example below to create a `.env` file in the project root:
   ```bash
   # Database
   DATABASE_URL=sqlite:///data/alumni.db

   # Flask
   SECRET_KEY=your-super-secret-key-change-this
   FLASK_ENV=development

   # Admin
   ADMIN_SECRET=adminpass
   ADMIN_HOST=

   # Optional: Admin subdomain
   # ADMIN_HOST=admin.example.com
   ```

5. **Initialize the database**
   ```bash
   python run.py
   ```
   The database will be created automatically on first run.

## Running the Application

```bash
python run.py
```

The application will be available at: `http://localhost:5000`

## Default Admin Credentials

For development/testing purposes:
- **Email:** admin@gmail.com
- **Password:** adminpass (from `ADMIN_SECRET` in `.env`)

⚠️ **Important:** Change these credentials in production!

## Accessing Admin Portal

Navigate to: `http://localhost:5000/admin/login`

## Project Structure

```
Alumini-Portal/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes/
│   │   ├── admin.py
│   │   └── student.py
│   └── templates/
│       ├── admin/
│       │   ├── admin_login.html
│       │   └── admin_dashboard.html
│       ├── student/
│       │   ├── login.html
│       │   ├── signup.html
│       │   ├── profile.html
│       │   ├── student_dashboard.html
│       │   ├── change-password.html
│       │   ├── careers.html
│       │   ├── directory.html
│       │   ├── donate.html
│       │   ├── events.html
│       │   ├── newsletter.html
│       │   ├── password_reset.html
│       │   ├── settings.html
│       │   └── support.html
│       └── layouts/
│           ├── _card_header.html
│           └── _flash.html
├── data/
├── .env
├── .gitignore
├── requirements.txt
├── run.py
└── README.md
```

## API Endpoints Overview

### Student Routes
- `POST /login` - Student login
- `POST /signup` - Student registration
- `GET /logout` - Student logout
- `GET /dashboard` - Student dashboard
- `GET /profile` - View/edit profile
- `POST /profile` - Update profile
- `GET /settings` - Account settings
- `POST /change-password` - Change password
- `GET /careers` - View job listings
- `GET /directory` - View alumni directory
- `GET /donate` - Donation page
- `GET /events` - View events
- `GET /newsletter` - Newsletter signup
- `GET /support` - Support page

### Student APIs
- `POST /api/complaints` - Submit complaint
- `GET /api/complaints` - Get complaints (own)
- `POST /api/transcripts` - Request transcript
- `GET /api/transcripts` - Get transcripts (own)
- `DELETE /api/transcripts/<id>` - Delete transcript
- `GET /api/notifications` - Get notifications
- `POST /api/notifications/mark_read` - Mark notifications as read

### Admin Routes
- `GET /admin/login` - Admin login page
- `POST /admin/login` - Admin login (accepts `adminEmail` & `adminPassword`)
- `GET /admin/dashboard` - Admin dashboard

### Admin APIs (Protected)
- `GET /api/users` - List all users
- `DELETE /api/users/<id>` - Delete user
- `POST /api/complaints/<id>/update` - Update complaint status
- `POST /api/transcripts/<id>/update` - Update transcript status
- `POST /api/transcripts/<id>/restore` - Restore deleted transcript
- `POST /api/admin/cleanup_trash` - Clean trash older than 30 days
- `POST /api/admin/permanent_delete/<id>` - Permanently delete transcript
- `POST /api/admin/permanent_delete_bulk` - Bulk permanent delete
- `POST /api/admin/restore_bulk` - Bulk restore transcripts
- `POST /api/notifications/mark_read` - Mark notifications as read (admin can mark others' notifications)
- `POST /api/notifications` - Send notifications to users

## Environment Variables Guide


| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | SQLite database path | `sqlite:///data/alumni.db` |
| `SECRET_KEY` | Flask session secret key | Any random string |
| `FLASK_ENV` | Environment mode | `development` or `production` |
| `ADMIN_SECRET` | Hardcoded admin password | `adminpass` |
| `ADMIN_HOST` | Optional admin subdomain | `admin.example.com` |

## Dependencies

Main packages (see `requirements.txt`):
- Flask - Web framework
- Flask-SQLAlchemy - ORM for database
- python-dotenv - Environment variable management
- Werkzeug - Utilities for WSGI applications

## Git Workflow

⚠️ **Important:** Never commit the `.env` file to version control!

The `.gitignore` file automatically excludes:
- `.env` files
- Python cache files (`__pycache__/`)
- Virtual environment files
- IDE configuration files
- Database files

## Database Schema

The application uses SQLite with the following main tables:
- `User` - Student and admin accounts
- `Complaint` - Student support tickets
- `Transcript` - Academic transcript requests
- `Event` - Community events
- `Job` - Career opportunities
- `Donation` - Alumni contributions
- `NewsletterSubscriber` - Newsletter subscribers
- `Notification` - System notifications

## Admin Login Details

**Hardcoded Admin Credentials (for development):**
- Email: `admin@gmail.com`
- Password: `adminpass` (configurable via `ADMIN_SECRET` in `.env`)

On first login with the hardcoded secret, an admin user is automatically created in the database.

## Troubleshooting

**Issue: "Invalid admin credentials" error**
- Ensure `ADMIN_SECRET` in `.env` matches the password you're entering
- Default is `adminpass`
- Email must be lowercase (e.g., `admin@gmail.com`)

**Issue: Database not found**
- The `data/` directory will be created automatically
- Ensure you have write permissions in the project directory

**Issue: Module not found**
- Activate your virtual environment: `venv\Scripts\activate` (Windows)
- Reinstall dependencies: `pip install -r requirements.txt`

**Issue: Port 5000 already in use**
- Change the port in `run.py`: `app.run(debug=True, port=5001)`


## License

This project is for educational and development purposes.

## Support

For issues or questions, please contact the development team.
