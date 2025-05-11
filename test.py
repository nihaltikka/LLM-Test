import os
import subprocess
import pickle
import sqlite3
import yaml
from flask import Flask, request, jsonify, session
import markdown
import xml.etree.ElementTree as ET
import hashlib
from datetime import datetime, timedelta
import jwt  # PyJWT
import requests
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key'  # Security Misconfiguration

# ======================
# Database Configuration
# ======================
def init_db():
    conn = sqlite3.connect('llm_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,  # Stored in plaintext (Cryptographic Failures)
            api_key TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    # Add default admin user with weak password
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'supersecretkey', 1)")
    conn.commit()
    conn.close()

init_db()

# =================================
# Vulnerabilities Implementation
# =================================

# 1. Security Misconfiguration
app.config.update(
    DEBUG=True,  # Debug mode in production
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    PREFERRED_URL_SCHEME='http'
)

# 2. Model Has No Source (No model provenance tracking)
class AIModel:
    def __init__(self):
        self.version = "1.0"
        # No information about training data, methodology, etc.
    
    def predict(self, input):
        # No input validation
        return "Generated output for: " + input

model = AIModel()  # Model lacks sufficient model card

# 3. Cryptographic Failures
def hash_password(password):
    # Weak hashing algorithm (should use bcrypt/scrypt/PBKDF2)
    return hashlib.md5(password.encode()).hexdigest()  # Cryptographic Failures

# 4. Broken Access Control
@app.route('/admin/dashboard')
def admin_dashboard():
    # No proper authorization check
    if 'username' in session:
        return "Welcome to admin dashboard"
    return "Access denied", 403  # But all users can access if they know the URL

# 5. Vulnerable and Outdated Components
# Using known vulnerable versions in requirements:
# flask==0.12.4 (known vulnerabilities)
# pyyaml==5.1 (with known unsafe load issues)

# 6. Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # No validation or restriction of URLs
    return requests.get(url).text  # SSRF Vulnerability

# 7. Insecure Design
@app.route('/login', methods=['POST'])
def login():
    # No rate limiting, no strong auth requirements
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('llm_users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")  # SQL Injection
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['is_admin'] = user[4]
        return "Login successful"
    return "Invalid credentials", 401

# 8. Software and Data Integrity Failures
@app.route('/update_model', methods=['POST'])
def update_model():
    # No signature verification for model updates
    new_model = request.files['model']
    new_model.save('current_model.pkl')
    return "Model updated", 200

# 9. Injection Vulnerabilities
@app.route('/execute_prompt', methods=['POST'])
def execute_prompt():
    prompt = request.json.get('prompt')
    # Direct prompt injection without sanitization
    output = subprocess.check_output(f'python run_model.py "{prompt}"', shell=True)
    return output.decode('utf-8')

# 10. Security Logging and Monitoring Failures
def log_event(event):
    # No proper logging mechanism
    with open('events.log', 'a') as f:
        f.write(f"{datetime.now()}: {event}\n")  # No sensitive data filtering

# 11. Identification and Authentication Failures
@app.route('/reset_password', methods=['POST'])
def reset_password():
    # Weak password reset functionality
    username = request.form['username']
    new_password = request.form['new_password']
    
    conn = sqlite3.connect('llm_users.db')
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'")
    conn.commit()
    conn.close()
    return "Password updated"

# ======================
# Additional Vulnerabilities
# ======================

# JWT with weak algorithm
def generate_token(user_id):
    # Using HS256 with weak secret
    return jwt.encode({'user_id': user_id}, 'weaksecret', algorithm='HS256')

# File upload vulnerability
@app.route('/upload', methods=['POST'])
def upload_file():
    # No proper file validation
    f = request.files['file']
    f.save(os.path.join('/var/www/uploads', f.filename))  # Path traversal possible
    return "File uploaded"

# Insecure direct object reference
@app.route('/user/profile/<int:user_id>')
def user_profile(user_id):
    # No authorization check
    conn = sqlite3.connect('llm_users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    return jsonify(user)

# ======================
# Test Cases
# ======================

def test_security_misconfiguration():
    return {
        "issue": "Debug mode enabled in production",
        "endpoint": "/",
        "headers": {"X-Forwarded-Proto": "http"}
    }

def test_cryptographic_failures():
    return {
        "username": "admin",
        "password": "admin123"  # Plaintext equivalent
    }

def test_broken_access_control():
    return {
        "url": "/admin/dashboard",
        "method": "GET"
    }

def test_ssrf():
    return {
        "url": "/fetch?url=file:///etc/passwd"
    }

def test_injection():
    return {
        "prompt": '"; rm -rf /; #'
    }

def test_auth_failure():
    return {
        "url": "/reset_password",
        "data": {"username": "admin", "new_password": "hacked"}
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Binding to all interfaces
