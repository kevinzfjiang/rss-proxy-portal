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
import filelock
import re
import urllib.parse
from logging.handlers import RotatingFileHandler
from flask import Flask, Response, render_template, request, redirect, url_for, g, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
DATABASE = 'feeds.db'
# Fetch interval can be configured via env FETCH_INTERVAL_SECONDS or CLI arg [2]. Default: 300 seconds (5 minutes)
try:
    FETCH_INTERVAL_SECONDS = int(os.environ.get('FETCH_INTERVAL_SECONDS', '300'))
    if FETCH_INTERVAL_SECONDS <= 0:
        FETCH_INTERVAL_SECONDS = 300
except Exception:
    FETCH_INTERVAL_SECONDS = 300
LOG_DIR = 'logs'
ACCESS_LOG_FILE = os.path.join(LOG_DIR, 'access.log')
FETCHER_LOCK_FILE = os.path.join(LOG_DIR, 'fetcher.lock')
fetcher_lock = filelock.FileLock(FETCHER_LOCK_FILE)

# Make SERVER_PORT configurable
try:
    # Try to get port from the first command-line argument
    SERVER_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    # Default to 8080 if no argument is provided or if it's not a valid number
    SERVER_PORT = 8080

# Optional second CLI argument to override fetch interval seconds
try:
    if len(sys.argv) > 2:
        cli_interval = int(sys.argv[2])
        if cli_interval > 0:
            FETCH_INTERVAL_SECONDS = cli_interval
except (ValueError, IndexError):
    pass

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
ACCEPT_HEADER = "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.7"
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
                db.execute('''
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
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

def ensure_settings_table():
    """Ensure the 'settings' table exists even for existing databases."""
    try:
        db = sqlite3.connect(DATABASE)
        with db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
        db.close()
    except Exception as e:
        print(f"Failed to ensure settings table: {e}")

def load_fetch_interval_from_db():
    """Load fetch interval from DB settings, seeding if missing."""
    global FETCH_INTERVAL_SECONDS
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        row = db.execute('SELECT value FROM settings WHERE key=?', ('fetch_interval_seconds',)).fetchone()
        if row:
            try:
                v = int(row['value'])
                if v > 0:
                    FETCH_INTERVAL_SECONDS = v
            except Exception:
                pass
        else:
            # Seed DB with current value
            with db:
                db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('fetch_interval_seconds', str(FETCH_INTERVAL_SECONDS)))
        db.close()
    except Exception as e:
        print(f"Failed to load fetch interval setting: {e}")

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
            headers = {
                'User-Agent': (feed['user_agent'] or DEFAULT_USER_AGENT)[:512],
                'Accept': ACCEPT_HEADER
            }
            if feed['cookie_data']:
                headers['Cookie'] = feed['cookie_data']
            
            session.headers.update(headers)
            response = session.get(feed['rss_url'], timeout=15)
            response.raise_for_status()

            # Preserve original bytes and content-type to avoid encoding issues (e.g., GB2312/GBK)
            content_bytes = response.content
            content_type = response.headers.get('Content-Type', 'application/rss+xml')
            # Try to determine charset (prefer XML prolog)
            encoding = None
            # 1) XML prolog
            head = content_bytes[:2048]
            try:
                head_text = head.decode('ascii', errors='ignore')
                m2 = re.search(r'<\?xml[^>]*encoding=["\']([A-Za-z0-9_\-]+)["\']', head_text)
                if m2:
                    encoding = m2.group(1)
            except Exception:
                pass
            # 2) From header if not set
            if not encoding:
                ct_lower = content_type.lower()
                m = re.search(r'charset\s*=\s*(["\']?)([a-z0-9_\-]+)\1', ct_lower)
                if m:
                    encoding = m.group(2)
            # 3) Fallback to requests' guessed encoding
            if not encoding and getattr(response, 'apparent_encoding', None):
                encoding = response.apparent_encoding
            # 4) Fallback to response.encoding
            if not encoding and response.encoding:
                encoding = response.encoding
            if not encoding:
                encoding = 'utf-8'  # best-effort default

            try:
                decoded_text = content_bytes.decode(encoding, errors='replace')
            except Exception:
                decoded_text = response.text  # last resort

            # Update the global cache with a rich entry
            with g_cache_lock:
                g_feed_cache[path] = {
                    'bytes': content_bytes,
                    'content_type': content_type,
                    'encoding': encoding,
                    'text': decoded_text,
                    'ts': time.time()
                }
            print(f"[{time.ctime()}] Successfully fetched and cached: {path} (encoding={encoding})")

        except requests.exceptions.RequestException as e:
            print(f"[{time.ctime()}] ERROR: Failed to fetch {path}: {e}")
            # Optionally update cache with error
            error_xml = f"<rss><channel><title>Proxy Error</title><description>Failed to fetch RSS: {e}</description></channel></rss>"
            error_bytes = error_xml.encode('utf-8')
            with g_cache_lock:
                # Only set error if feed isn't already in cache
                g_feed_cache.setdefault(path, {
                    'bytes': error_bytes,
                    'content_type': 'application/rss+xml; charset=utf-8',
                    'encoding': 'utf-8',
                    'text': error_xml,
                    'ts': time.time()
                })

def background_fetcher():
    """A loop that runs in a background thread."""
    def _current_interval():
        try:
            db = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
            row = db.execute('SELECT value FROM settings WHERE key=?', ('fetch_interval_seconds',)).fetchone()
            db.close()
            if row:
                try:
                    v = int(row['value'])
                    if 30 <= v <= 86400:
                        return v
                except Exception:
                    pass
            # Fallback to global
            return FETCH_INTERVAL_SECONDS
        except Exception:
            return FETCH_INTERVAL_SECONDS

    while True:
        fetch_all_feeds()
        next_int = _current_interval()
        print(f"[{time.ctime()}] Next fetch in {next_int} seconds...")
        time.sleep(next_int)

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
    try:
        # Open (or create) the lock file and try to acquire an exclusive, non-blocking lock.
        fetcher_lock.acquire(timeout=0)
        print("Acquired fetcher lock; starting background fetcher thread...")
        fetch_thread = threading.Thread(target=background_fetcher, daemon=True)
        fetch_thread.start()
        return True
    except filelock.Timeout:
        print("Fetcher lock not acquired; another process likely running the fetcher.")
        return False

# Ensure DB and logging ready when running under gunicorn as well
if not os.path.exists(DATABASE):
    init_db()
else:
    # Try to upgrade any legacy plaintext passwords
    upgrade_existing_passwords()
    ensure_settings_table()
    load_fetch_interval_from_db()
setup_logging()

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route("/")

def index():

    """Serves the admin portal UI."""

    db = get_db()

    feeds = db.execute('SELECT path_name, rss_url FROM feeds ORDER BY path_name').fetchall()

    # Humanize interval for display

    try:

        s = int(FETCH_INTERVAL_SECONDS)

        if s < 60:

            fetch_interval_human = f"{s} seconds"

        else:

            fetch_interval_human = f"{s // 60} minutes" if s % 60 == 0 else f"{s // 60}m {s % 60}s"

    except Exception:

        fetch_interval_human = "unknown"

    return render_template("index.html", feeds=feeds, is_admin=is_admin(), fetch_interval_human=fetch_interval_human)

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    if not is_admin():
        flash('Admin privileges required.', 'error')
        return redirect(url_for('index'))
    global FETCH_INTERVAL_SECONDS
    db = get_db()
    if request.method == 'POST':
        val = request.form.get('fetch_interval_seconds','').strip()
        try:
            new_val = int(val)
            if new_val < 30 or new_val > 86400:
                raise ValueError('Out of range')
            with db:
                db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('fetch_interval_seconds', str(new_val)))
            FETCH_INTERVAL_SECONDS = new_val
            flash('Fetch interval updated.', 'info')
            return redirect(url_for('settings'))
        except Exception:
            flash('Invalid interval. Please enter 30–86400 seconds.', 'error')
    # Read current value from DB if exists, else use global
    row = db.execute('SELECT value FROM settings WHERE key=?', ('fetch_interval_seconds',)).fetchone()
    if row:
        try:
            current = int(row['value'])
        except Exception:
            current = FETCH_INTERVAL_SECONDS
    else:
        current = FETCH_INTERVAL_SECONDS
    s = int(current)
    current_human = f"{s} seconds" if s < 60 else (f"{s // 60} minutes" if s % 60 == 0 else f"{s // 60}m {s % 60}s")
    return render_template("settings.html", current_interval=current, current_interval_human=current_human)

@app.route("/add", methods=["POST"])
@login_required
def add_feed():
    """Handles the form submission to add a new feed."""
    if not is_admin():
        flash('Admin privileges required to add feeds.', 'error')
        return redirect(url_for('index'))
    try:
        path_name = request.form['path_name'].strip()
        rss_url = request.form['rss_url'].strip()
        cookie_data = request.form.get('cookie_data','').strip()
        user_agent = (request.form.get('user_agent','') or DEFAULT_USER_AGENT)[:512]

        # Basic validation for URL
        parsed = urllib.parse.urlparse(rss_url)
        if parsed.scheme not in ('http','https') or not parsed.netloc:
            flash('Invalid RSS URL. Use http(s) URLs only.', 'error')
            return redirect(url_for('index'))
        # Validate proxy path characters (allow letters, digits, dash, underscore, dot, and slashes)
        if not re.match(r'^[A-Za-z0-9_./-]+$', path_name):
            flash('Invalid proxy path. Allowed: letters, digits, dash, underscore, dot, and /.', 'error')
            return redirect(url_for('index'))
        if len(path_name) > 200:
            flash('Proxy path too long.', 'error')
            return redirect(url_for('index'))
        
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
        # Support both legacy str cache and new dict cache
        if isinstance(content, dict) and 'bytes' in content:
            ct = content.get('content_type', 'application/rss+xml') or 'application/rss+xml'
            # Ensure charset present
            if 'charset' not in ct.lower():
                base = ct.split(';')[0].strip()
                enc = content.get('encoding') or 'utf-8'
                ct = f"{base}; charset={enc}"
            return Response(content['bytes'], content_type=ct)
        else:
            return Response(str(content), mimetype='application/rss+xml; charset=utf-8')
    else:
        # If not in cache, maybe it was just added. Try to fetch it.
        # For a production system, you'd be more patient.
        error_xml = f"<rss><channel><title>Not Found</title><description>Feed '/feed/{path_name}' not found or not yet cached.</description></channel></rss>"
        return Response(error_xml, status=404, content_type='application/rss+xml; charset=utf-8')

@app.route('/favicon.ico')
def favicon():
    # 1x1 transparent GIF
    gif = (b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
    resp = Response(gif, mimetype='image/gif')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp



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
    return render_template("login.html")

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



@app.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
        if request.method == 'POST':
                current = request.form.get('current','')
                new = request.form.get('new','')
                confirm = request.form.get('confirm','')
                if new != confirm:
                        flash('New passwords do not match.', 'error')
                        return render_template("change_password.html")
                row = query_user_by_username(current_user.username)
                if not row:
                        flash('User not found.', 'error')
                        return render_template("change_password.html")
                stored = row['password']
                # Verify current using hashed if available, else plaintext
                try:
                    valid = check_password_hash(stored, current)
                except Exception:
                    valid = (isinstance(stored, str) and ':' not in stored and stored == current)
                if not valid:
                        flash('Current password incorrect.', 'error')
                        return render_template("change_password.html")
                try:
                        db = get_db()
                        with db:
                                db.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(new), row['id']))
                        flash('Password updated successfully.', 'info')
                        return redirect(url_for('index'))
                except Exception as e:
                        flash(f'Failed to update password: {e}', 'error')
        return render_template("change_password.html")



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
        return render_template("manage_users.html", users=users)

# --- Main Execution ---

@app.before_request
def _start_bg():
    # Guarded startup: attempt to start fetcher once per process using a file lock.
    if not getattr(app, '_fetcher_started', False):
        started = start_fetcher_if_master()
        # Mark as attempted to avoid retry spam per request
        app._fetcher_started = True



