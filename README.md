# Helmet GPS Tracker - Setup Guide

## 📁 File Structure

```
project/
├── app.py              # Flask backend with SQLite database
├── mydb.db            # SQLite database (auto-created)
├── templates/
│   ├── index.html     # Login page
│   └── dashboard.html # GPS tracking dashboard
```

## 🚀 Installation & Setup

### 1. Install Required Dependencies

```bash
pip install flask flask-cors werkzeug
```

### 2. Create Templates Folder

```bash
mkdir templates
```

### 3. Move HTML Files to Templates

```bash
mv index.html templates/
mv dashboard.html templates/
```

### 4. Run the Application

```bash
python app.py
```

The server will start on `http://0.0.0.0:5000`

## 🔑 Default Login Credentials

The application creates a default admin account on first run:
- **Username:** `admin`
- **Password:** `admin123`

**⚠️ IMPORTANT:** Change these credentials in production!

## 📊 Database Structure

### Tables Created Automatically:

#### 1. **users**
- `id` - Primary key (auto-increment)
- `username` - Unique username
- `password_hash` - Hashed password (secure, not plain text)
- `email` - User email (optional)
- `created_at` - Account creation timestamp
- `last_login` - Last login timestamp

#### 2. **gps_logs**
- `id` - Primary key (auto-increment)
- `latitude` - GPS latitude coordinate
- `longitude` - GPS longitude coordinate
- `speed` - Speed in km/h
- `satellites` - Number of satellites connected
- `altitude` - Altitude in meters
- `timestamp` - Auto-generated log timestamp
- `date` - Date string from GPS module
- `time` - Time string from GPS module
- `alcohol_raw` - Raw alcohol sensor value
- `alcohol_status` - Alcohol detection status (Normal/Warning/Danger)

#### 3. **user_sessions**
**Purpose:** Manages user authentication sessions and "Remember Me" functionality.

This table stores authentication tokens that allow users to stay logged in across browser sessions. When a user logs in:
- A unique token is generated and stored
- The token is sent to the user's browser
- On subsequent visits, the token is validated
- Tokens expire after 1 day (or 30 days with "Remember Me")

**Why it's needed:**
- Provides secure session management
- Allows "Remember Me" functionality
- Enables API authentication with tokens
- Tracks active user sessions

**Columns:**
- `id` - Primary key
- `user_id` - Foreign key linking to users table
- `token` - Unique session token (like a temporary password)
- `created_at` - When the session was created
- `expires_at` - When the session expires

#### 4. **sqlite_sequence**
**Purpose:** Internal SQLite system table (automatically created).

This is NOT a table you create - SQLite creates it automatically when you use AUTOINCREMENT in your tables. It tracks the highest ID number used in each table with auto-incrementing primary keys.

**What it does:**
- Ensures ID numbers are never reused
- Prevents conflicts when inserting new records
- Maintains the sequence counter for each table

**Example:**
If you insert 5 GPS logs (IDs 1-5) then delete log #5, the next log will be ID 6 (not 5 again). This prevents data conflicts.

**Important:** Don't modify or delete this table - it's managed automatically by SQLite!

## 🔧 Available Database Helper Functions

### User Management
```python
create_user(username, password, email=None)
get_user_by_username(username)
get_user_by_id(user_id)
verify_user_password(username, password)
update_last_login(user_id)
```

### GPS Data
```python
log_gps_data(data)
get_recent_gps_logs(limit=100, date_filter=None)
clear_all_gps_logs()  # NEW - Clear all GPS history
get_gps_statistics()   # NEW - Get GPS statistics
```

### Session Management
```python
create_user_session(user_id, remember_me=False)
verify_session_token(token)
delete_session_token(token)
```

### General Query Execution
```python
execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False)
```

## 🌐 API Endpoints

### Authentication Endpoints

#### POST `/api/login`
Login with username and password
```json
{
  "username": "admin",
  "password": "admin123",
  "remember_me": false
}
```

Response:
```json
{
  "success": true,
  "message": "Login successful",
  "token": "session_token_here",
  "user": {
    "id": 1,
    "username": "admin"
  }
}
```

#### POST `/api/logout`
Logout and invalidate session
```json
{
  "token": "session_token_here"
}
```

#### POST `/api/register`
Register new user
```json
{
  "username": "newuser",
  "password": "password123",
  "email": "user@example.com"
}
```

### GPS Data Endpoints

#### POST `/api/gps`
Receive GPS data from ESP32 (no authentication required)
```json
{
  "lat": 14.123456,
  "lng": 121.123456,
  "speed": 45.5,
  "sat": 8,
  "alt": 120.5,
  "hour": 14,
  "minute": 30,
  "second": 45,
  "day": 11,
  "month": 2,
  "year": 2026,
  "alcohol_raw": 150,
  "alcohol_status": "Normal"
}
```

#### GET `/api/gps`
Get latest GPS data (requires authentication)

#### GET `/api/gps/history?limit=100&date=2026-02-11`
Get GPS history logs with optional date filter (requires authentication)

Response:
```json
{
  "success": true,
  "count": 100,
  "logs": [
    {
      "id": 1,
      "latitude": 14.123456,
      "longitude": 121.123456,
      "speed": 45.5,
      "satellites": 8,
      "altitude": 120.5,
      "timestamp": "2026-02-11 14:30:45",
      "date": "11/02/2026",
      "time": "14:30:45",
      "alcohol_raw": 150,
      "alcohol_status": "Normal"
    }
  ]
}
```

#### DELETE `/api/gps/clear`
Clear all GPS history (requires authentication)

#### GET `/api/gps/statistics`
Get GPS statistics (requires authentication)

Response:
```json
{
  "success": true,
  "statistics": {
    "total_records": 1500,
    "max_speed": 85.5,
    "avg_satellites": 7.8,
    "max_altitude": 450.2,
    "total_distance": 0
  }
}
```

#### GET `/api/user`
Get current logged-in user information (requires authentication)

Response:
```json
{
  "success": true,
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "last_login": "2026-02-11 14:30:00"
}
```

## 🔒 Security Features

1. **Password Hashing** - Uses Werkzeug's secure password hashing
2. **Session Management** - Token-based authentication
3. **Protected Routes** - Dashboard requires login
4. **CSRF Protection** - Session-based authentication
5. **Configurable Session Duration** - Remember me functionality

## 📱 ESP32 Integration

Your ESP32 should POST data to:
```
POST http://your-server-ip:5000/api/gps
Content-Type: application/json
```

No authentication required for ESP32 GPS data posting.

## 🎨 Features

### Login Page
- Modern, animated UI matching dashboard design
- Form validation
- Error handling
- Remember me functionality
- Responsive design

### Dashboard
- **Real-time GPS tracking** with live updates
- **Interactive map** with OpenStreetMap integration
- **Speed, altitude, and satellite** information display
- **Alcohol sensor monitoring** with status indicators
- **Auto-refresh capabilities** for map and data
- **User authentication** with logout functionality
- **GPS History & Logs Viewer** with:
  - Searchable and filterable data table
  - Statistics dashboard (total records, max speed, average satellites, distance traveled)
  - Date filtering
  - CSV export functionality
  - Clear history option
- **Responsive design** for desktop and mobile devices
- **Visual indicators** for GPS quality and connection status

## ✨ New Features & Improvements

### Dashboard Enhancements
1. **Logout Button** - Secure logout with session cleanup
2. **User Display** - Shows currently logged-in username
3. **GPS History Modal** - Interactive history viewer with:
   - Beautiful modal interface matching dashboard design
   - Real-time statistics (total records, max speed, avg satellites, distance traveled)
   - Sortable and filterable data table
   - Date range filtering
   - CSV export functionality
   - Clear all history option
4. **Distance Calculation** - Automatically calculates total distance traveled using GPS coordinates
5. **Status Badges** - Color-coded alcohol status indicators (Normal/Warning/Danger)
6. **Enhanced Data Display** - Formatted timestamps and better data presentation

### Backend Improvements
1. **Enhanced Database Functions:**
   - `get_recent_gps_logs()` - Now supports date filtering
   - `clear_all_gps_logs()` - Clear all GPS history
   - `get_gps_statistics()` - Calculate GPS statistics

2. **New API Endpoints:**
   - `GET /api/user` - Get current user information
   - `DELETE /api/gps/clear` - Clear all GPS history
   - `GET /api/gps/statistics` - Get GPS statistics
   - Enhanced `GET /api/gps/history` with date filtering

3. **Better Code Organization:**
   - Reusable database helper functions
   - No raw SQL queries in routes
   - Consistent error handling
   - Proper function documentation

### Security Features
- Session-based authentication
- Protected API endpoints
- Secure password hashing
- Token-based session management
- Automatic session expiration

## 🛠️ Customization

### Adding New Database Functions

Use the `execute_query()` helper function:

```python
def your_custom_query(param):
    query = 'SELECT * FROM table WHERE column = ?'
    return execute_query(query, (param,), fetch_all=True)
```

### Creating Additional Users

```python
from app import create_user

create_user('username', 'password', 'email@example.com')
```

## 📝 Notes

- Database file `mydb.db` is created automatically on first run
- All GPS data is logged to the database
- Sessions expire after 1 day (24 hours) or 30 days with "Remember Me"
- The application uses Flask sessions and token-based authentication

## 🐛 Troubleshooting

### Database Issues
If you encounter database errors, delete `mydb.db` and restart the application to recreate it.

### Login Issues
Make sure the templates folder contains both `index.html` and `dashboard.html`.

### ESP32 Connection
Ensure your ESP32 can reach the server IP and port 5000 is open.

## 📄 License

This project is provided as-is for educational and personal use.
