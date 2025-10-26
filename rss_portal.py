import http.server
import socketserver
import threading
import time
import requests
import http.cookiejar
import os
import sqlite3
import sys  # Import sys to read command-line arguments
from flask import Flask, Response, render_template_string, request, redirect, url_for, g

# --- Configuration ---
DATABASE = 'feeds.db'
FETCH_INTERVAL_SECONDS = 300  # 5 minutes
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
    """Initialize the database and create the table if it doesn't exist."""
    print("Initializing database...")
    with socketserver.TCPServer(("", 0), None) as s: # A bit of a trick to use app_context
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
            print("Database initialized.")

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
            <p>Add a new feed configuration to proxy. The proxy will fetch it every 5 minutes.</p>
        </div>

        <div class="section">
            <h2>Add New Feed</h2>
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
                        <form action="/delete" method="POST" class="delete-form" onsubmit="return confirm('Are you sure?');">
                            <input type="hidden" name="path_name" value="{{ feed.path_name }}">
                            <button type="submit" class="delete-button">Delete</button>
                        </form>
                    </li>
                {% endfor %}
                </ul>
            {% else %}
                <p>No feeds configured yet.</p>
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
    return render_template_string(HTML_TEMPLATE, feeds=feeds)

@app.route("/add", methods=["POST"])
def add_feed():
    """Handles the form submission to add a new feed."""
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
def delete_feed():
    """Handles deleting a feed."""
    try:
        path_name = request.form['path_name']
        db = get_db()
        with db:
            db.execute('DELETE FROM feeds WHERE path_name = ?', (path_name,))
        
        # Remove from cache
        with g_cache_lock:
            g_feed_cache.pop(path_name, None) # Safely remove if it exists
            
        print(f"Deleted feed: {path_name}")
    except Exception as e:
        print(f"ERROR: Failed to delete feed: {e}")
        
    return redirect(url_for('index'))

@app.route("/feed/<path:path_name>")
def serve_feed(path_name):
    """Serves the cached RSS content."""
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

# --- Main Execution ---

if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()

    print("Starting background fetcher thread...")
    fetch_thread = threading.Thread(target=background_fetcher, daemon=True)
    fetch_thread.start()

    print(f"Starting Flask server on http://0.0.0.0:{SERVER_PORT}")
    print(f"Admin portal running on http://localhost:{SERVER_PORT}")
    print(f"To use a different port, run: python {sys.argv[0]} [port_number]")
    app.run(host='0.0.0.0', port=SERVER_PORT)

