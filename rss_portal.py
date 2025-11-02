import http.server
import socketserver
import threading
import time
import requests
import http.cookiejar
import os
import sqlite3
import sys  # Import sys to read command-line arguments
import logging
import fcntl
from logging.handlers import RotatingFileHandler
from flask import Flask, Response, render_template_string, request, redirect, url_for, g, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
DATABASE = 'feeds.db'
FETCH_INTERVAL_SECONDS = 300  # 5 minutes
LOG_DIR = 'logs'
ACCESS_LOG_FILE = os.path.join(LOG_DIR, 'access.log')
FETCHER_LOCK_FILE = os.path.join(LOG_DIR, 'fetcher.lock')
_fetcher_lock_fp = None
# Make SERVER_PORT configurable
try:
    # Try to get port from the first command-line argument
    SERVER_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    # Default to 8080 if no argument is provided or if it's not a valid number
    SERVER_PORT = 8080

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
# --- End Configuration ---

# In-memory cache for the RSS content
g_feed_cache = {}
g_cache_lock = threading.Lock()

# --- Database Functions ---

def get_db():
    """Get a database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return db

def init_db():
    """Initialize the database and create the tables if they don't exist."""
    print("Initializing database...")
    with socketserver.TCPServer(("", 0), None) as s:  # Use app_context helper
        app = Flask(__name__)
        with app.app_context():
            db = get_db()
            with db:
                db.execute('''
                    CREATE TABLE IF NOT EXISTS feeds (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        path_name TEXT UNIQUE NOT NULL,
                        rss_url TEXT NOT NULL,
                        cookie_data TEXT,
                        user_agent TEXT
                    )
                ''')
                db.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('admin','user'))
                    )
                ''')
                # Seed default admin if not exists
                existing = db.execute('SELECT id FROM users WHERE username=?', ('admin',)).fetchone()
                if not existing:
                    default_admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin')
                    hashed = generate_password_hash(default_admin_pass)
                    db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('admin', hashed, 'admin'))
                    if default_admin_pass == 'admin':
                        print("Seeded default admin user: admin/admin (please change immediately)")
                    else:
                        print("Seeded default admin with ADMIN_PASSWORD from environment.")
            print("Database initialized.")

def upgrade_existing_passwords():
    """Upgrade legacy plaintext passwords to hashed where possible for admin; warn for others."""
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        cur = db.execute('SELECT id, username, password FROM users')
        rows = cur.fetchall()
        for row in rows:
            pwd = row['password']
            # Treat values without a colon as legacy plaintext; Werkzeug hashes include a method prefix followed by ':'
            if isinstance(pwd, str) and ':' not in pwd:
                if row['username'] == 'admin' and pwd == 'admin':
                    new_hash = generate_password_hash('admin')
                    db.execute('UPDATE users SET password=? WHERE id=?', (new_hash, row['id']))
                    print('Upgraded admin password to hashed default.')
                else:
                    print(f"WARNING: User '{row['username']}' has a legacy plaintext password. Ask the user to log in once to upgrade or change password.")
        db.commit()
        db.close()
    except Exception as e:
        print(f"Password upgrade check failed: {e}")

# --- Background Fetcher ---

def fetch_all_feeds():
    """Fetches all RSS feeds defined in the database."""
    print(f"[{time.ctime()}] Starting background fetch for all feeds...")
    
    # We must create a new DB connection for the thread
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        feeds = db.execute('SELECT * FROM feeds').fetchall()
        db.close()
    except sqlite3.Error as e:
        print(f"[{time.ctime()}] ERROR: Could not read feeds from database: {e}")
        return

    for feed in feeds:
        path = feed['path_name']
        print(f"[{time.ctime()}] Fetching feed: {path}")
        try:
            session = requests.Session()
            headers = {'User-Agent': feed['user_agent'] or DEFAULT_USER_AGENT}
            if feed['cookie_data']:
                headers['Cookie'] = feed['cookie_data']
            
            session.headers.update(headers)
            response = session.get(feed['rss_url'], timeout=15)
            response.raise_for_status()

            # Update the global cache
            with g_cache_lock:
                g_feed_cache[path] = response.text
            print(f"[{time.ctime()}] Successfully fetched and cached: {path}")

        except requests.exceptions.RequestException as e:
            print(f"[{time.ctime()}] ERROR: Failed to fetch {path}: {e}")
            # Optionally update cache with error
            error_xml = f"<rss><channel><title>Proxy Error</title><description>Failed to fetch RSS: {e}</description></channel></rss>"
            with g_cache_lock:
                # Only set error if feed isn't already in cache
                g_feed_cache.setdefault(path, error_xml)

def background_fetcher():
    """A loop that runs in a background thread."""
    while True:
        fetch_all_feeds()
        print(f"[{time.ctime()}] Next fetch in {FETCH_INTERVAL_SECONDS} seconds...")
        time.sleep(FETCH_INTERVAL_SECONDS)

# --- Web Application (Flask) ---

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

def query_user_by_username(username):
    db = get_db()
    row = db.execute('SELECT id, username, password, role FROM users WHERE username=?', (username,)).fetchone()
    return row

def query_user_by_id(user_id):
    db = get_db()
    row = db.execute('SELECT id, username, role FROM users WHERE id=?', (user_id,)).fetchone()
    return row

@login_manager.user_loader
def load_user(user_id):
    row = query_user_by_id(user_id)
    if row:
        return User(row['id'], row['username'], row['role'])
    return None

def is_admin():
    return current_user.is_authenticated and getattr(current_user, 'role', '') == 'admin'

# Configure access logging
def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(ACCESS_LOG_FILE, maxBytes=1_000_000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

def start_fetcher_if_master():
    """Start background fetcher only if we can acquire a process-wide lock."""
    global _fetcher_lock_fp
    try:
        # Open (or create) the lock file and try to acquire an exclusive, non-blocking lock.
        _fetcher_lock_fp = open(FETCHER_LOCK_FILE, 'w')
        fcntl.flock(_fetcher_lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("Acquired fetcher lock; starting background fetcher thread...")
        fetch_thread = threading.Thread(target=background_fetcher, daemon=True)
        fetch_thread.start()
        return True
    except Exception as e:
        print("Fetcher lock not acquired; another process likely running the fetcher.")
        return False

# Ensure DB and logging ready when running under gunicorn as well
if not os.path.exists(DATABASE):
    init_db()
else:
    # Try to upgrade any legacy plaintext passwords
    upgrade_existing_passwords()
setup_logging()

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# The HTML template for the admin portal, all in one string
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSS Proxy Portal</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; background-color: #f4f7f6; color: #333; max-width: 900px; margin: 20px auto; padding: 20px; }
        h1, h2 { color: #2a2a2a; }
        .container { background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .section { padding: 25px; border-bottom: 1px solid #eee; }
        .section:last-child { border-bottom: none; }
        form { display: grid; grid-template-columns: 150px 1fr; gap: 15px; align-items: center; }
        label { font-weight: 600; text-align: right; }
        input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        textarea { min-height: 80px; font-family: monospace; }
        .button-container { grid-column: 2; }
        button { background-color: #007bff; color: white; padding: 10px 18px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .feed-list ul { list-style: none; padding-left: 0; }
        .feed-list li { display: flex; justify-content: space-between; align-items: center; background: #fdfdfd; padding: 12px 15px; border: 1px solid #eee; border-radius: 5px; margin-bottom: 10px; }
        .feed-list a { font-weight: 600; color: #0056b3; text-decoration: none; word-break: break-all; }
        .feed-list a:hover { text-decoration: underline; }
        .feed-url { font-family: monospace; font-size: 0.9em; }
        .delete-form { margin: 0; }
        .delete-button { background: #dc3545; font-size: 14px; padding: 8px 12px; }
        .delete-button:hover { background: #c82333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="section">
            <h1>RSS Proxy Portal</h1>
            {% if current_user.is_authenticated %}
                <p>Logged in as: <strong>{{ current_user.username }}</strong> ({{ current_user.role }})
                | <a href="{{ url_for('logout') }}">Logout</a></p>
            {% else %}
                <p><a href="{{ url_for('login') }}">Login</a></p>
            {% endif %}
            <p>Add a new feed configuration to proxy. The proxy will fetch it every 5 minutes.</p>
        </div>

        <div class="section">
            <h2>Add New Feed</h2>
            {% if not is_admin %}
            <p>Only administrators can add feeds. Please login as admin.</p>
            {% else %}
            <form action="/add" method="POST">
                <label for="path_name">Proxy Path:</label>
                <input type="text" id="path_name" name="path_name" placeholder="e.g., RSS-chip.xml (must be unique)" required>
                
                <label for="rss_url">Source RSS URL:</label>
                <input type="text" id="rss_url" name="rss_url" placeholder="https://example.com/feed.xml" required>
                
                <label for="cookie_data">Cookie Data:</label>
                <textarea id="cookie_data" name="cookie_data" placeholder="Paste raw cookie string, e.g., session=...; user=..."></textarea>
                
                <label for="user_agent">User-Agent:</label>
                <input type="text" id="user_agent" name="user_agent" placeholder="Optional. Defaults to a standard Chrome User-Agent.">

                <div class="button-container">
                    <button type="submit">Add Feed</button>
                </div>
            </form>
            {% endif %}
        </div>

        <div class="section feed-list">
            <h2>Current Feeds</h2>
            {% if feeds %}
                <ul>
                {% for feed in feeds %}
                    <li>
                        <div>
                            <a href="{{ url_for('serve_feed', path_name=feed.path_name) }}" target="_blank">
                                /feed/{{ feed.path_name }}
                            </a>
                            <div class="feed-url" title="Source URL">{{ feed.rss_url }}</div>
                        </div>
                        {% if is_admin %}
                        <form action="/delete" method="POST" class="delete-form" onsubmit="return confirm('Are you sure?');">
                            <input type="hidden" name="path_name" value="{{ feed.path_name }}">
                            <button type="submit" class="delete-button">Delete</button>
                        </form>
                        {% endif %}
                    </li>
                {% endfor %}
                </ul>
            {% else %}
                <p>No feeds configured yet.</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>Access Logs</h2>
            {% if is_admin %}
            <p><a href="{{ url_for('view_logs') }}" target="_blank">View access logs</a></p>
            {% else %}
            <p>Only administrators can view logs.</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>Account</h2>
            {% if current_user.is_authenticated %}
                <p><a href="{{ url_for('change_password') }}">Change password</a></p>
            {% endif %}
            {% if is_admin %}
                <p><a href="{{ url_for('manage_users') }}">Manage users</a></p>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    """Serves the admin portal UI."""
    db = get_db()
    feeds = db.execute('SELECT path_name, rss_url FROM feeds ORDER BY path_name').fetchall()
    return render_template_string(HTML_TEMPLATE, feeds=feeds, is_admin=is_admin())

@app.route("/add", methods=["POST"])
@login_required
def add_feed():
    """Handles the form submission to add a new feed."""
    if not is_admin():
        flash('Admin privileges required to add feeds.', 'error')
        return redirect(url_for('index'))
    try:
        path_name = request.form['path_name']
        rss_url = request.form['rss_url']
        cookie_data = request.form['cookie_data']
        user_agent = request.form['user_agent'] or DEFAULT_USER_AGENT
        
        db = get_db()
        with db:
            db.execute(
                'INSERT INTO feeds (path_name, rss_url, cookie_data, user_agent) VALUES (?, ?, ?, ?)',
                (path_name, rss_url, cookie_data, user_agent)
            )
        app.logger.info(f"add_feed path={path_name} user={current_user.username} ip={request.remote_addr}")
        # Trigger an immediate fetch for the new feed
        print(f"New feed added: {path_name}. Triggering immediate fetch.")
        threading.Thread(target=fetch_all_feeds).start() # Run in a new thread to not block UI
        
    except sqlite3.IntegrityError:
        print(f"ERROR: Failed to add feed. Path '{path_name}' already exists.")
        # We could add a proper error message back to the user, but redirect is simpler for now
    except Exception as e:
        print(f"ERROR: Failed to add feed: {e}")

    return redirect(url_for('index'))

@app.route("/delete", methods=["POST"])
@login_required
def delete_feed():
    """Handles deleting a feed."""
    if not is_admin():
        flash('Admin privileges required to delete feeds.', 'error')
        return redirect(url_for('index'))
    try:
        path_name = request.form['path_name']
        db = get_db()
        with db:
            db.execute('DELETE FROM feeds WHERE path_name = ?', (path_name,))
        
        # Remove from cache
        with g_cache_lock:
            g_feed_cache.pop(path_name, None) # Safely remove if it exists
            
        print(f"Deleted feed: {path_name}")
        app.logger.info(f"delete_feed path={path_name} user={current_user.username} ip={request.remote_addr}")
    except Exception as e:
        print(f"ERROR: Failed to delete feed: {e}")
        
    return redirect(url_for('index'))

@app.route("/feed/<path:path_name>")
def serve_feed(path_name):
    """Serves the cached RSS content."""
    user = current_user.username if current_user.is_authenticated else 'anonymous'
    app.logger.info(f"serve_feed path={path_name} user={user} ip={request.remote_addr}")
    content = None
    with g_cache_lock:
        content = g_feed_cache.get(path_name)
    
    if content:
        return Response(content, mimetype='application/rss+xml; charset=utf-8')
    else:
        # If not in cache, maybe it was just added. Try to fetch it.
        # For a production system, you'd be more patient.
        error_xml = f"<rss><channel><title>Not Found</title><description>Feed '/feed/{path_name}' not found or not yet cached.</description></channel></rss>"
        return Response(error_xml, status=404, mimetype='application/rss+xml; charset=utf-8')

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f4f7f6; color: #333; display: flex; align-items: center; justify-content: center; height: 100vh; }
        .card { background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); width: 360px; }
        h2 { margin-top: 0; }
        label { display: block; margin: 12px 0 6px; font-weight: 600; }
        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { margin-top: 16px; width: 100%; background-color: #007bff; color: white; padding: 10px 18px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .msg { color: #c00; margin-top: 8px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Login</h2>
        <form method="POST">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Login</button>
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="msg">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
    </div>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        row = query_user_by_username(username)
        if row:
            stored = row['password']
            ok = False
            # Try hashed verification first (Werkzeug supports pbkdf2, scrypt, etc.)
            try:
                ok = check_password_hash(stored, password)
            except Exception:
                ok = False
            if not ok:
                # Legacy plaintext support; upgrade on success
                if isinstance(stored, str) and ':' not in stored and stored == password:
                    ok = True
                    try:
                        db = get_db()
                        with db:
                            db.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(password), row['id']))
                        print(f"Upgraded password for user '{username}' to hashed.")
                    except Exception as e:
                        print(f"Failed to upgrade password hash for {username}: {e}")
            if ok:
                user = User(row['id'], row['username'], row['role'])
                login_user(user)
                app.logger.info(f"login user={username} ip={request.remote_addr}")
                return redirect(url_for('index'))
        flash('Invalid username or password.', 'error')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.info(f"logout user={username} ip={request.remote_addr}")
    return redirect(url_for('index'))

@app.route('/logs')
@login_required
def view_logs():
    if not is_admin():
        flash('Admin privileges required to view logs.', 'error')
        return redirect(url_for('index'))
    try:
        if os.path.exists(ACCESS_LOG_FILE):
            with open(ACCESS_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            content = 'No logs yet.'
    except Exception as e:
        content = f'Error reading logs: {e}'
    return Response(content, mimetype='text/plain')

CHANGE_PW_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>Change Password</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;background:#f4f7f6;padding:40px} .card{background:#fff;padding:24px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.05);max-width:420px;margin:auto} label{display:block;margin:12px 0 6px;font-weight:600} input{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px} button{margin-top:16px;background:#007bff;color:#fff;border:0;border-radius:5px;padding:10px 18px;cursor:pointer}</style>
</head>
<body>
<div class=card>
<h2>Change Password</h2>
<form method=post>
<label>Current password</label><input type=password name=current required>
<label>New password</label><input type=password name=new required>
<label>Confirm new password</label><input type=password name=confirm required>
<button type=submit>Change</button>
</form>
{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        {% for category, message in messages %}
            <div class="msg">{{ message }}</div>
        {% endfor %}
    {% endif %}
{% endwith %}
</div>
</body></html>
"""

@app.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
        if request.method == 'POST':
                current = request.form.get('current','')
                new = request.form.get('new','')
                confirm = request.form.get('confirm','')
                if new != confirm:
                        flash('New passwords do not match.', 'error')
                        return render_template_string(CHANGE_PW_TEMPLATE)
                row = query_user_by_username(current_user.username)
                if not row:
                        flash('User not found.', 'error')
                        return render_template_string(CHANGE_PW_TEMPLATE)
                stored = row['password']
                # Verify current using hashed if available, else plaintext
                try:
                    valid = check_password_hash(stored, current)
                except Exception:
                    valid = (isinstance(stored, str) and ':' not in stored and stored == current)
                if not valid:
                        flash('Current password incorrect.', 'error')
                        return render_template_string(CHANGE_PW_TEMPLATE)
                try:
                        db = get_db()
                        with db:
                                db.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(new), row['id']))
                        flash('Password updated successfully.', 'info')
                        return redirect(url_for('index'))
                except Exception as e:
                        flash(f'Failed to update password: {e}', 'error')
        return render_template_string(CHANGE_PW_TEMPLATE)

MANAGE_USERS_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Manage Users</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;background:#f4f7f6;padding:40px} .card{background:#fff;padding:24px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.05);max-width:720px;margin:auto} table{width:100%;border-collapse:collapse} th,td{border:1px solid #eee;padding:8px} label{display:block;margin:8px 0 4px;font-weight:600} input,select{width:100%;padding:8px;border:1px solid #ddd;border-radius:5px} button{margin-top:8px;background:#007bff;color:#fff;border:0;border-radius:5px;padding:8px 14px;cursor:pointer}</style>
</head>
<body>
<div class=card>
<h2>Manage Users</h2>
<h3>Create User</h3>
<form method=post>
<label>Username</label><input name=username required>
<label>Password</label><input name=password type=password required>
<label>Role</label><select name=role><option value=user>User</option><option value=admin>Admin</option></select>
<button type=submit>Create</button>
</form>
<h3>Existing Users</h3>
<table><tr><th>ID</th><th>Username</th><th>Role</th></tr>
{% for u in users %}<tr><td>{{u.id}}</td><td>{{u.username}}</td><td>{{u.role}}</td></tr>{% endfor %}
</table>
{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        {% for category, message in messages %}
            <div class="msg">{{ message }}</div>
        {% endfor %}
    {% endif %}
{% endwith %}
</div>
</body></html>
"""

@app.route('/users', methods=['GET','POST'])
@login_required
def manage_users():
        if not is_admin():
                flash('Admin privileges required.', 'error')
                return redirect(url_for('index'))
        db = get_db()
        if request.method == 'POST':
                username = request.form.get('username','').strip()
                password = request.form.get('password','')
                role = request.form.get('role','user')
                try:
                        with db:
                                db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, generate_password_hash(password), role))
                        flash('User created.', 'info')
                except sqlite3.IntegrityError:
                        flash('Username already exists.', 'error')
        users = db.execute('SELECT id, username, role FROM users ORDER BY id').fetchall()
        return render_template_string(MANAGE_USERS_TEMPLATE, users=users)

# --- Main Execution ---

@app.before_request
def _start_bg():
    # Guarded startup: attempt to start fetcher once per process using a file lock.
    if not getattr(app, '_fetcher_started', False):
        started = start_fetcher_if_master()
        # Mark as attempted to avoid retry spam per request
        app._fetcher_started = True

if __name__ == "__main__":
    print(f"Starting Flask server on http://0.0.0.0:{SERVER_PORT}")
    print(f"Admin portal running on http://localhost:{SERVER_PORT}")
    print(f"To use a different port, run: python {sys.argv[0]} [port_number]")
    app.run(host='0.0.0.0', port=SERVER_PORT)

