RSS Proxy Portal

A self-hosted web portal to fetch and proxy restricted RSS feeds.

This application helps when RSS feeds are protected by IP, require login cookies, or check for a specific User-Agent.

It runs a lightweight web server that:

- Fetches restricted feeds in the background from a server that does have access (e.g., your home server).
- Provides a modern web UI to add, manage, and delete feeds.
- Serves the cached RSS content at a new, simple URL (e.g., /feed/my-feed.xml) that any RSS reader can use.

Features

- Modern UI: Refreshed dark theme with card layout, better forms, copy-to-clipboard links.
- Background Fetching: Configurable interval; fetches all feeds periodically.
- Custom Credentials: Set cookies and User-Agent strings per feed.
- Custom URL Paths: Define your own proxy path (e.g., RSS-chip.xml) for each feed.
- Persistent Storage: SQLite database (feeds.db) stores configurations and settings.
- Settings Page: Admin UI to configure fetch interval, persisted to DB.
- Robust Encoding Handling: Preserves original bytes and sets proper charset to avoid garbled text (e.g., Chinese GBK/GB2312, UTF-8).
- Containerized: Includes a Dockerfile for easy deployment.

Authentication & Roles

- Login required for admin operations. Default admin user is seeded on first run: username "admin", password "admin". Change it immediately.
- Regular (non-admin) users can log in but cannot add or delete feeds or view logs.
- Set a strong Flask secret key via environment variable SECRET_KEY in production.
 - Passwords are stored hashed. You can set the initial admin password via ADMIN_PASSWORD environment variable.

Installation & Usage

There are two primary ways to run this application:

Method 1: Docker (Recommended)

This is the easiest and most reliable way to run the portal, as it bundles all dependencies.

Option A: Use the prebuilt image from Docker Hub

Pull the image:

```bash
docker pull yadiman/rss-proxy-portal:latest
```

Run the Container:

```bash
docker run -d \
  -p 8080:8080 \
  -v rss-portal-data:/app \
  -e SECRET_KEY=$(openssl rand -hex 32) \
  -e ADMIN_PASSWORD='your-strong-admin-password' \
  -e FETCH_INTERVAL_SECONDS=300 \
  --name my-rss-proxy \
  --restart always \
  yadiman/rss-proxy-portal:latest
```

Option B: Build the Image Locally

Build the Image:
From the directory containing the Dockerfile, run:

```bash
docker build -t rss-proxy-portal .
```


Create a Persistent Volume:
This is critical for ensuring your feeds.db file (which stores all your added feeds) is not lost when you restart the container.

```bash
docker volume create rss-portal-data
```


Run the Container:

```bash
docker run -d \
  -p 8080:8080 \
  -v rss-portal-data:/app \
  -e SECRET_KEY=$(openssl rand -hex 32) \
  -e ADMIN_PASSWORD='your-strong-admin-password' \
  -e FETCH_INTERVAL_SECONDS=300 \
  --name my-rss-proxy \
  --restart always \
  rss-proxy-portal
```


-p 8080:8080: Maps your host port 8080 to the container's port 8080.

-v rss-portal-data:/app: Mounts the volume to store the feeds.db file.

--restart always: (Optional) Ensures the container automatically restarts if it stops or the server reboots.

Method 2: Python Virtual Environment (Manual)

If you prefer to run the app directly on your host:

Create a Virtual Environment:

```bash
python3 -m venv venv
```


Activate the Environment:

```bash
source venv/bin/activate
# On Windows, use: venv\Scripts\activate
```


Install Dependencies:

```bash
pip install -r requirements.txt
```


Run the Application:

```bash
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
python rss_portal.py
# You can also specify a port:
# python rss_portal.py 8000
# You can also specify fetch interval (seconds) as an optional second argument:
# python rss_portal.py 8080 120
# Or via environment variable:
# export FETCH_INTERVAL_SECONDS=120
# python rss_portal.py
```


How to Use the Portal

Open the Web UI:
Open your browser and navigate to http://localhost:8080 (or your server's IP at that port).

Add a Feed:

Proxy Path: The new path you want your feed to have (e.g., my-project-feed.xml).

Source RSS URL: The original, restricted RSS feed URL.

Cookie Data: The raw cookie string needed for authentication (e.g., session=...; user=...).

User-Agent: (Optional) The User-Agent string required by the server. Defaults to a standard Chrome agent if left blank.

Click "Add Feed"

Access Your New Feed:
Your new, proxied feed is now available at http://localhost:8080/feed/my-project-feed.xml. You can add this new URL to any RSS reader (like Feedly, Inoreader, etc.).

Authentication

- Visit http://localhost:8080/login to sign in.
- Default admin is admin/admin. After login, you can add and delete feeds.
 - Create users at http://localhost:8080/users (admin-only). Passwords are stored securely (hashed).

Access Logs

- Admins can view access logs at http://localhost:8080/logs
- Logs are stored in logs/access.log with rotation (max 1MB, 5 backups)

Configuration & Production notes

- Consider running with gunicorn:

  ```bash
  gunicorn -w 2 -b 0.0.0.0:8080 rss_portal:app
  ```

- Ensure SECRET_KEY and ADMIN_PASSWORD are set via environment variables.

Settings & Configuration

- Fetch interval can be configured in three ways:
  1) Environment variable: `FETCH_INTERVAL_SECONDS` (in seconds)
  2) CLI argument: `python rss_portal.py [port] [fetch_interval_seconds]`
  3) Admin UI: Settings page at `http://localhost:8080/settings` (persists to DB)

- The background fetcher reads the latest interval from the DB each cycle, so changes in Settings take effect across processes.

Encoding Handling

- The proxy preserves the source bytes and sets the response `Content-Type` with the correct `charset`.
- Charset detection order: XML prolog `<?xml ... encoding="..."?>` > response header > apparent encoding > requests' encoding; default `utf-8`.
- This avoids Chinese content being garbled when upstream serves `text/xml` without explicit charset.

Password reset

If you forget the admin password, you can reset it directly in the SQLite database. Then log in once to trigger an automatic upgrade to a secure hash, or change it via the UI.

Reset admin to 'admin':

```bash
sqlite3 feeds.db "update users set password='admin' where username='admin';"
```

After resetting, log in with admin/admin and immediately change the password at http://localhost:8080/change_password.

Docker Compose Example

You can also use Docker Compose for easier management:

```yaml
version: "3.8"
services:
  rss-proxy-portal:
    image: yadiman/rss-proxy-portal:latest
    container_name: rss-proxy-portal
    ports:
      - "8080:8080"
    volumes:
      - rss-portal-data:/app
    environment:
      SECRET_KEY: ${SECRET_KEY}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      FETCH_INTERVAL_SECONDS: ${FETCH_INTERVAL_SECONDS:-300}
    restart: always

volumes:
  rss-portal-data:
```

Start with:

```bash
export SECRET_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD='your-strong-admin-password'
export FETCH_INTERVAL_SECONDS=300
docker compose up -d
```

This repository also includes:

- `docker-compose.yml`: ready-to-use service definition
- `.env.example`: sample environment variables (copy to `.env` and edit)
Changelog

- 2025-11-02:
  - UI overhaul (dark theme, improved forms and feed cards, link copy button)
  - Settings page to configure fetch interval (persisted to DB)
  - Fetch interval configurable via env/CLI/UI and read per-cycle from DB
  - Encoding fix: preserve bytes, prefer XML prolog encoding, set charset in response
  - Feed card URL overflow fixed