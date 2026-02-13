from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import random
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)  # allow all origins
app.secret_key = secrets.token_hex(32)  # Generate a secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# ============================================
# EMAIL CONFIGURATION (OPTIONAL)
# ============================================
# Set EMAIL_ENABLED = True and configure SMTP settings to enable email functionality
EMAIL_ENABLED = False  # Change to True to enable email

# SMTP Configuration (Gmail example)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your-email@gmail.com'  # Your email
SMTP_PASSWORD = 'your-app-password'      # Your app password (not regular password)
SENDER_EMAIL = 'your-email@gmail.com'
SENDER_NAME = 'Helmet GPS Tracker'

# Email import (only if enabled)
if EMAIL_ENABLED:
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        print("Email functionality enabled")
    except ImportError:
        EMAIL_ENABLED = False
        print("Email libraries not installed. Email functionality disabled.")

# Database configuration
DATABASE = 'mydb.db'

# Store latest GPS data from ESP32
latest_data = {
    "lat": None,
    "lng": None,
    "speed": None,
    "sat": None,
    "alt": None,
    "hour": None,
    "minute": None,
    "second": None,
    "day": None,
    "month": None,
    "year": None,
    "alcohol_raw": None,
    "alcohol_status": None
}


# ============================================
# DATABASE HELPER FUNCTIONS
# ============================================

def get_db_connection():
    """
    Create and return a database connection.
    
    Returns:
        sqlite3.Connection: Database connection object
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    return conn


def init_db():
    """
    Initialize the database with required tables.
    Creates users table and GPS logs table if they don't exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create GPS logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gps_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            latitude REAL,
            longitude REAL,
            speed REAL,
            satellites INTEGER,
            altitude REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            date TEXT,
            time TEXT,
            alcohol_raw INTEGER,
            alcohol_status TEXT
        )
    ''')
    
    # Create sessions table for token-based auth
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create password reset tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")


def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """
    Execute a database query with proper connection handling.
    
    Args:
        query (str): SQL query to execute
        params (tuple): Query parameters for parameterized queries
        fetch_one (bool): If True, fetch and return one result
        fetch_all (bool): If True, fetch and return all results
        commit (bool): If True, commit the transaction
    
    Returns:
        Result of the query or None
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(query, params)
        
        if commit:
            conn.commit()
            return cursor.lastrowid
        
        if fetch_one:
            result = cursor.fetchone()
            return dict(result) if result else None
        
        if fetch_all:
            results = cursor.fetchall()
            return [dict(row) for row in results]
        
        return None
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    
    finally:
        conn.close()


def create_user(username, password, email=None):
    """
    Create a new user in the database.
    
    Args:
        username (str): Username for the new user
        password (str): Plain text password (will be hashed)
        email (str): Optional email address
    
    Returns:
        int: User ID if successful, None otherwise
    """
    password_hash = generate_password_hash(password)
    
    query = '''
        INSERT INTO users (username, password_hash, email)
        VALUES (?, ?, ?)
    '''
    
    return execute_query(query, (username, password_hash, email), commit=True)


def get_user_by_username(username):
    """
    Retrieve a user by username.
    
    Args:
        username (str): Username to search for
    
    Returns:
        dict: User data if found, None otherwise
    """
    query = 'SELECT * FROM users WHERE username = ?'
    return execute_query(query, (username,), fetch_one=True)


def get_user_by_id(user_id):
    """
    Retrieve a user by ID.
    
    Args:
        user_id (int): User ID to search for
    
    Returns:
        dict: User data if found, None otherwise
    """
    query = 'SELECT * FROM users WHERE id = ?'
    return execute_query(query, (user_id,), fetch_one=True)


def verify_user_password(username, password):
    """
    Verify user credentials.
    
    Args:
        username (str): Username
        password (str): Plain text password to verify
    
    Returns:
        dict: User data if credentials are valid, None otherwise
    """
    user = get_user_by_username(username)
    
    if user and check_password_hash(user['password_hash'], password):
        return user
    
    return None


def update_last_login(user_id):
    """
    Update the last login timestamp for a user.
    
    Args:
        user_id (int): User ID
    
    Returns:
        bool: True if successful
    """
    query = 'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?'
    execute_query(query, (user_id,), commit=True)
    return True


def log_gps_data(data):
    """
    Log GPS data to the database.
    
    Args:
        data (dict): GPS data dictionary
    
    Returns:
        int: Log ID if successful, None otherwise
    """
    query = '''
        INSERT INTO gps_logs 
        (latitude, longitude, speed, satellites, altitude, date, time, alcohol_raw, alcohol_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    
    date_str = f"{data.get('day')}/{data.get('month')}/{data.get('year')}"
    time_str = f"{data.get('hour')}:{data.get('minute')}:{data.get('second')}"
    
    params = (
        data.get('lat'),
        data.get('lng'),
        data.get('speed'),
        data.get('sat'),
        data.get('alt'),
        date_str,
        time_str,
        data.get('alcohol_raw'),
        data.get('alcohol_status')
    )
    
    return execute_query(query, params, commit=True)


def get_recent_gps_logs(limit=100, date_filter=None):
    """
    Get recent GPS logs from the database with optional date filtering.
    
    Args:
        limit (int): Maximum number of logs to retrieve
        date_filter (str): Optional date string to filter by (format: YYYY-MM-DD)
    
    Returns:
        list: List of GPS log dictionaries
    """
    if date_filter:
        query = '''
            SELECT * FROM gps_logs 
            WHERE DATE(timestamp) = DATE(?)
            ORDER BY timestamp DESC 
            LIMIT ?
        '''
        return execute_query(query, (date_filter, limit), fetch_all=True)
    else:
        query = '''
            SELECT * FROM gps_logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        '''
        return execute_query(query, (limit,), fetch_all=True)


def create_user_session(user_id, remember_me=False):
    """
    Create a new session token for a user.
    
    Args:
        user_id (int): User ID
        remember_me (bool): If True, session expires in 30 days, else 1 day
    
    Returns:
        str: Session token
    """
    token = secrets.token_urlsafe(32)
    expires_days = 30 if remember_me else 1
    expires_at = datetime.now() + timedelta(days=expires_days)
    
    query = '''
        INSERT INTO user_sessions (user_id, token, expires_at)
        VALUES (?, ?, ?)
    '''
    
    execute_query(query, (user_id, token, expires_at), commit=True)
    return token


def verify_session_token(token):
    """
    Verify a session token and return the associated user.
    
    Args:
        token (str): Session token
    
    Returns:
        dict: User data if token is valid, None otherwise
    """
    query = '''
        SELECT u.* FROM users u
        JOIN user_sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP
    '''
    return execute_query(query, (token,), fetch_one=True)


def delete_session_token(token):
    """
    Delete a session token (logout).
    
    Args:
        token (str): Session token to delete
    """
    query = 'DELETE FROM user_sessions WHERE token = ?'
    execute_query(query, (token,), commit=True)


def clear_all_gps_logs():
    """
    Delete all GPS logs from the database.
    Use with caution!
    
    Returns:
        bool: True if successful
    """
    query = 'DELETE FROM gps_logs'
    execute_query(query, commit=True)
    return True


def get_gps_statistics():
    """
    Get statistics about GPS logs.
    
    Returns:
        dict: Statistics including total count, max speed, avg satellites, etc.
    """
    stats = {
        'total_records': 0,
        'max_speed': 0,
        'avg_satellites': 0,
        'max_altitude': 0,
        'total_distance': 0
    }
    
    # Get total count
    count_query = 'SELECT COUNT(*) as count FROM gps_logs'
    count_result = execute_query(count_query, fetch_one=True)
    if count_result:
        stats['total_records'] = count_result['count']
    
    # Get max speed
    speed_query = 'SELECT MAX(speed) as max_speed FROM gps_logs'
    speed_result = execute_query(speed_query, fetch_one=True)
    if speed_result and speed_result['max_speed']:
        stats['max_speed'] = speed_result['max_speed']
    
    # Get average satellites
    sat_query = 'SELECT AVG(satellites) as avg_sat FROM gps_logs'
    sat_result = execute_query(sat_query, fetch_one=True)
    if sat_result and sat_result['avg_sat']:
        stats['avg_satellites'] = round(sat_result['avg_sat'], 1)
    
    # Get max altitude
    alt_query = 'SELECT MAX(altitude) as max_alt FROM gps_logs'
    alt_result = execute_query(alt_query, fetch_one=True)
    if alt_result and alt_result['max_alt']:
        stats['max_altitude'] = alt_result['max_alt']
    
    return stats


def create_password_reset_token(user_id):
    """
    Create a password reset token for a user.
    
    Args:
        user_id (int): User ID
    
    Returns:
        str: Reset token
    """
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)  # Token expires in 1 hour
    
    query = '''
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES (?, ?, ?)
    '''
    
    execute_query(query, (user_id, token, expires_at), commit=True)
    return token


def verify_reset_token(token):
    """
    Verify a password reset token.
    
    Args:
        token (str): Reset token
    
    Returns:
        dict: User data if token is valid and not used, None otherwise
    """
    query = '''
        SELECT u.*, r.id as reset_id FROM users u
        JOIN password_reset_tokens r ON u.id = r.user_id
        WHERE r.token = ? AND r.expires_at > CURRENT_TIMESTAMP AND r.used = 0
    '''
    return execute_query(query, (token,), fetch_one=True)


def mark_reset_token_used(token):
    """
    Mark a reset token as used.
    
    Args:
        token (str): Reset token
    """
    query = 'UPDATE password_reset_tokens SET used = 1 WHERE token = ?'
    execute_query(query, (token,), commit=True)


def update_user_password(user_id, new_password):
    """
    Update a user's password.
    
    Args:
        user_id (int): User ID
        new_password (str): New plain text password (will be hashed)
    
    Returns:
        bool: True if successful
    """
    password_hash = generate_password_hash(new_password)
    query = 'UPDATE users SET password_hash = ? WHERE id = ?'
    execute_query(query, (password_hash, user_id), commit=True)
    return True


def get_user_by_email(email):
    """
    Retrieve a user by email.
    
    Args:
        email (str): Email address to search for
    
    Returns:
        dict: User data if found, None otherwise
    """
    query = 'SELECT * FROM users WHERE email = ?'
    return execute_query(query, (email,), fetch_one=True)


def reset_user_password(username):
    """
    Reset a user's password to a randomly generated one.
    
    Args:
        username (str): Username to reset password for
    
    Returns:
        str: New password if successful, None otherwise
    """
    import random
    import string
    
    # Generate a random password
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    password_hash = generate_password_hash(new_password)
    
    query = 'UPDATE users SET password_hash = ? WHERE username = ?'
    execute_query(query, (password_hash, username), commit=True)
    
    return new_password


def update_user_password(user_id, new_password):
    """
    Update a user's password.
    
    Args:
        user_id (int): User ID
        new_password (str): New plain text password
    
    Returns:
        bool: True if successful
    """
    password_hash = generate_password_hash(new_password)
    query = 'UPDATE users SET password_hash = ? WHERE id = ?'
    execute_query(query, (password_hash, user_id), commit=True)
    return True


# ============================================
# AUTHENTICATION DECORATOR
# ============================================

def login_required(f):
    """
    Decorator to require login for protected routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# ROUTES
# ============================================

@app.route("/")
def index():
    """Serve login page"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")


@app.route("/register")
def register_page():
    """Serve register page"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("register.html")


@app.route("/forgot-password")
def forgot_password_page():
    """Serve forgot password page"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("forgot-password.html")


@app.route("/reset-password/<token>")
def reset_password_page(token):
    """Serve reset password page with token"""
    return render_template("reset-password.html", token=token)


@app.route("/register")
def register_page():
    """Serve register page"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("register.html")


@app.route("/forgot-password")
def forgot_password_page():
    """Serve forgot password page"""
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("forgot-password.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """Serve dashboard HTML (protected route)"""
    return render_template("dashboard.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Handle login requests.
    Expects JSON with username and password.
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    remember_me = data.get('remember_me', False)
    
    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        }), 400
    
    # Verify credentials
    user = verify_user_password(username, password)
    
    if user:
        # Update last login
        update_last_login(user['id'])
        
        # Create session
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.permanent = remember_me
        
        # Create token for API access
        token = create_user_session(user['id'], remember_me)
        
        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user['id'],
                "username": user['username']
            }
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Handle logout requests"""
    # Get token from request if provided
    token = request.json.get('token') if request.json else None
    
    if token:
        delete_session_token(token)
    
    # Clear session
    session.clear()
    
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    }), 200


@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Handle user registration.
    Expects JSON with username, password, and optional email.
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        }), 400
    
    # Check if user already exists
    if get_user_by_username(username):
        return jsonify({
            "success": False,
            "message": "Username already exists"
        }), 409
    
    # Check if email already exists
    if email and get_user_by_email(email):
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409
    
    # Create new user
    user_id = create_user(username, password, email)
    
    if user_id:
        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "user_id": user_id
        }), 201
    else:
        return jsonify({
            "success": False,
            "message": "Registration failed"
        }), 500


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    """
    Handle forgot password request.
    Expects JSON with email.
    """
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400
    
    # Check if user exists
    user = get_user_by_email(email)
    
    # Always return success to prevent email enumeration attacks
    if not user:
        return jsonify({
            "success": True,
            "message": "If an account with that email exists, a password reset link has been sent."
        }), 200
    
    # Create reset token
    reset_token = create_password_reset_token(user['id'])
    
    # Create reset link
    reset_link = f"http://localhost:5000/reset-password/{reset_token}"
    
    # TODO: Send email with reset link
    # For now, just print to console (you can add email later)
    print(f"\n{'='*60}")
    print(f"PASSWORD RESET REQUEST")
    print(f"{'='*60}")
    print(f"User: {user['username']}")
    print(f"Email: {user['email']}")
    print(f"Reset Link: {reset_link}")
    print(f"{'='*60}\n")
    
    # In production, you would send an email here using Flask-Mail or similar
    # Example email content:
    # Subject: Password Reset Request
    # Body: Click the following link to reset your password: {reset_link}
    #       This link will expire in 1 hour.
    
    return jsonify({
        "success": True,
        "message": "If an account with that email exists, a password reset link has been sent.",
        "reset_link": reset_link  # Remove this in production!
    }), 200


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    """
    Handle password reset.
    Expects JSON with token and new password.
    """
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    
    if not token or not new_password:
        return jsonify({
            "success": False,
            "message": "Token and new password are required"
        }), 400
    
    if len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters long"
        }), 400
    
    # Verify token
    user_data = verify_reset_token(token)
    
    if not user_data:
        return jsonify({
            "success": False,
            "message": "Invalid or expired reset token"
        }), 400
    
    # Update password
    update_user_password(user_data['id'], new_password)
    
    # Mark token as used
    mark_reset_token_used(token)
    
    return jsonify({
        "success": True,
        "message": "Password reset successful! You can now login with your new password."
    }), 200


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    """
    Handle forgot password requests.
    Resets the password to a random one and returns it.
    In production, this should send an email instead.
    """
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({
            "success": False,
            "message": "Username is required"
        }), 400
    
    # Check if user exists
    user = get_user_by_username(username)
    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404
    
    # Reset password
    new_password = reset_user_password(username)
    
    if new_password:
        return jsonify({
            "success": True,
            "message": "Password has been reset successfully",
            "new_password": new_password
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Failed to reset password"
        }), 500


@app.route("/api/gps", methods=["POST"])
def receive_gps():
    """
    API for ESP32 to POST GPS data.
    This endpoint doesn't require authentication for IoT devices.
    """
    global latest_data
    data = request.json
    
    latest_data = {
        "lat": data.get("lat"),
        "lng": data.get("lng"),
        "speed": data.get("speed"),
        "sat": data.get("sat"),
        "alt": data.get("alt"),
        "hour": data.get("hour"),
        "minute": data.get("minute"),
        "second": data.get("second"),
        "day": data.get("day"),
        "month": data.get("month"),
        "year": data.get("year"),
        "alcohol_raw": data.get("alcohol_raw"),
        "alcohol_status": data.get("alcohol_status")
    }
    
    # Log to database
    log_gps_data(latest_data)
    
    print("Received GPS:", latest_data)
    return jsonify({"status": "ok"}), 200


@app.route("/api/gps", methods=["GET"])
@login_required
def get_gps():
    """
    API for dashboard to GET latest GPS data.
    Protected route - requires login.
    """
    return jsonify(latest_data), 200


@app.route("/api/gps/history", methods=["GET"])
@login_required
def get_gps_history():
    """
    Get GPS history logs with optional date filter.
    Query parameters: 
        - limit (default 100)
        - date (optional, format: YYYY-MM-DD)
    """
    limit = request.args.get('limit', 100, type=int)
    date_filter = request.args.get('date', None)
    
    logs = get_recent_gps_logs(limit, date_filter)
    
    return jsonify({
        "success": True,
        "count": len(logs),
        "logs": logs
    }), 200


@app.route("/api/gps/clear", methods=["DELETE"])
@login_required
def clear_gps_history():
    """
    Clear all GPS history logs.
    Protected route - requires login.
    """
    try:
        clear_all_gps_logs()
        return jsonify({
            "success": True,
            "message": "All GPS history cleared successfully"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/api/gps/statistics", methods=["GET"])
@login_required
def get_statistics():
    """
    Get GPS statistics.
    Protected route - requires login.
    """
    stats = get_gps_statistics()
    return jsonify({
        "success": True,
        "statistics": stats
    }), 200


@app.route("/api/user", methods=["GET"])
@login_required
def get_user_info():
    """
    Get current logged-in user information.
    Protected route - requires login.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    if user:
        return jsonify({
            "success": True,
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "last_login": user['last_login']
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404


# ============================================
# INITIALIZATION
# ============================================

if __name__ == "__main__":
    # Initialize database on startup
    init_db()
    
    # Create a default admin user for testing (remove in production)
    if not get_user_by_username('admin'):
        create_user('admin', 'admin123', 'admin@example.com')
        print("Default admin user created (username: admin, password: admin123)")
    
    app.run(host="0.0.0.0", port=5000, debug=True)
