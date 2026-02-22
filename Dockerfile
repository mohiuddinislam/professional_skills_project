# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install Node.js for building the frontend
RUN apt-get update && apt-get install -y \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy frontend package files
COPY frontend/package*.json ./frontend/

# Install frontend dependencies
WORKDIR /app/frontend
RUN npm install

# Copy the rest of the application's code
WORKDIR /app
COPY . .

# Build the frontend
WORKDIR /app/frontend
RUN npm run build

# Move back to app directory
WORKDIR /app

# Create data directory for cache
RUN mkdir -p /app/data

# Make port 8080 available (Cloud Run default)
EXPOSE 8080

# Set environment variable for production
ENV PYTHONUNBUFFERED=1

# Use gunicorn for production with proper timeout settings
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 300 --access-logfile - --error-logfile - app:app
