# Use an official Python 3.11 slim-buster image as the base
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
# --no-cache-dir: Don't store the package cache, keeping the image small
RUN pip install --no-cache-dir -r requirements.txt

# Copy your main application script into the container
COPY rss_portal.py .

# The script is set to run on port 8080 by default.
# Expose this port so we can map to it from the host.
EXPOSE 8080

# When the container starts, run the application.
# We explicitly pass "8080" as the port number,
# matching the EXPOSE instruction.
CMD ["python", "rss_portal.py", "8080"]
