RSS Proxy Portal

A simple, self-hosted web portal to fetch and proxy restricted RSS feeds.

This application is designed to solve a common problem: accessing RSS feeds that are protected by IP, require login cookies, or check for a specific User-Agent.

It runs a lightweight web server that:

Fetches these restricted feeds in the background from a server that does have access (e.g., your home server).

Provides a simple web UI to add, manage, and delete feeds.

Serves the cached RSS content at a new, simple, public URL (e.g., /feed/my-feed.xml) that any RSS reader can use.

!

Features

Simple Web UI: A clean interface (built with Flask) to add and remove feeds.

Background Fetching: A background thread automatically fetches all feeds every 5 minutes.

Custom Credentials: Set custom cookies and User-Agent strings for each feed individually.

Custom URL Paths: Define your own proxy path (e.g., RSS-chip.xml) for each feed.

Persistent Storage: Uses a simple SQLite database (feeds.db) to store your configurations.

Containerized: Includes a Dockerfile for easy deployment.

Installation & Usage

There are two primary ways to run this application:

Method 1: Docker (Recommended)

This is the easiest and most reliable way to run the portal, as it bundles all dependencies.

Build the Image:
From the directory containing the Dockerfile, run:

docker build -t rss-proxy-portal .


Create a Persistent Volume:
This is critical for ensuring your feeds.db file (which stores all your added feeds) is not lost when you restart the container.

docker volume create rss-portal-data


Run the Container:

docker run -d \
  -p 8080:8080 \
  -v rss-portal-data:/app \
  --name my-rss-proxy \
  --restart always \
  rss-proxy-portal


-p 8080:8080: Maps your host port 8080 to the container's port 8080.

-v rss-portal-data:/app: Mounts the volume to store the feeds.db file.

--restart always: (Optional) Ensures the container automatically restarts if it stops or the server reboots.

Method 2: Python Virtual Environment (Manual)

If you prefer to run the app directly on your host:

Create a Virtual Environment:

python3 -m venv venv


Activate the Environment:

source venv/bin/activate
# On Windows, use: venv\Scripts\activate


Install Dependencies:

pip install -r requirements.txt


Run the Application:

python rss_portal.py
# You can also specify a port:
# python rss_portal.py 8000


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