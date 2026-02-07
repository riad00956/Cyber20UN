
import os
import subprocess
import threading
import sqlite3
import time
import hashlib
import secrets
import json
from datetime import datetime
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import re
import shutil
import sys
import traceback
import atexit

# Flask & SocketIO Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600 * 24  # 24 hours
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Render.com compatible settings (polling only)
socketio = SocketIO(app,
                   cors_allowed_origins="*",
                   transports=['polling'],  # Render.com doesn't support WebSocket
                   async_mode='threading',
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=1e8,  # 100MB max for large code
                   logger=False,
                   engineio_logger=False)

# Configuration
USER_DB = "cyber_vault.db"
LOG_DB = "terminal_history.db"
PROJECT_DIR = "user_projects"
SECRET_KEY_FILE = "secret_key.txt"
SETTINGS_FILE = "server_settings.json"

# Create directories
os.makedirs(PROJECT_DIR, exist_ok=True)

# Server settings
def load_settings():
    default_settings = {
        'max_file_size': 10485760,  # 10MB
        'max_code_length': 50000,   # 50KB
        'command_timeout': 30,      # 30 seconds
        'session_timeout': 3600,    # 1 hour
        'allowed_extensions': ['.py', '.txt', '.md', '.json', '.html', '.css', '.js'],
        'max_files_per_user': 100,
        'backup_interval': 3600,    # 1 hour
        'log_retention_days': 30
    }
    
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                loaded = json.load(f)
                default_settings.update(loaded)
        except:
            pass
    
    return default_settings

SETTINGS = load_settings()

# Save settings
def save_settings():
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(SETTINGS, f, indent=2)

# Cleanup function
def cleanup():
    print("🔄 Performing cleanup...")
    try:
        # Backup databases
        if os.path.exists(USER_DB):
            shutil.copy2(USER_DB, f"{USER_DB}.backup")
        if os.path.exists(LOG_DB):
            shutil.copy2(LOG_DB, f"{LOG_DB}.backup")
        
        # Clean old logs
        with sqlite3.connect(LOG_DB) as conn:
            cutoff = datetime.now().timestamp() - (SETTINGS['log_retention_days'] * 86400)
            conn.execute("DELETE FROM terminal_logs WHERE time < ?", 
                        (datetime.fromtimestamp(cutoff).isoformat(),))
        
        print("✅ Cleanup completed")
    except Exception as e:
        print(f"⚠️ Cleanup error: {e}")

# Register cleanup on exit
atexit.register(cleanup)

# Generate secure access keys
def generate_access_keys():
    if not os.path.exists(SECRET_KEY_FILE):
        keys = {
            'server_key': secrets.token_urlsafe(32),
            'access_key': secrets.token_urlsafe(32),
            'ghost_key': secrets.token_urlsafe(32)
        }
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(f"Server Key: {keys['server_key']}\n")
            f.write(f"Access Key: {keys['access_key']}\n")
            f.write(f"Ghost Key: {keys['ghost_key']}\n")
        print(f"🚀 Access Keys Generated:")
        print(f"🔑 Main Interface: https://[YOUR_APP].onrender.com/?key={keys['server_key']}")
        print(f"🔑 Access Portal: https://[YOUR_APP].onrender.com/access/{keys['access_key']}")
        print(f"🔑 Ghost Mode: https://[YOUR_APP].onrender.com/ghost/{keys['ghost_key']}")
        return keys
    else:
        try:
            with open(SECRET_KEY_FILE, 'r') as f:
                lines = f.readlines()
                keys = {}
                for line in lines:
                    if 'Server Key:' in line:
                        keys['server_key'] = line.split(': ')[1].strip()
                    elif 'Access Key:' in line:
                        keys['access_key'] = line.split(': ')[1].strip()
                    elif 'Ghost Key:' in line:
                        keys['ghost_key'] = line.split(': ')[1].strip()
                return keys
        except:
            os.remove(SECRET_KEY_FILE)
            return generate_access_keys()

ACCESS_KEYS = generate_access_keys()

# Enhanced password hashing
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + hash_obj.hex()

def verify_password(password, hashed):
    salt = hashed[:32]  # First 32 chars are salt
    return hashed == hash_password(password, salt)

# --- Database Initialize ---
def init_dbs():
    """Initialize databases with proper error handling"""
    try:
        # User & File Database
        with sqlite3.connect(USER_DB) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP,
                            is_active BOOLEAN DEFAULT 1)''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS files 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            filename TEXT NOT NULL,
                            code TEXT,
                            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            file_size INTEGER,
                            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            try:
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_files_user_time 
                               ON files(username, time DESC)''')
            except:
                pass
    
        # Terminal Logs Database
        with sqlite3.connect(LOG_DB) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS terminal_logs 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            command TEXT NOT NULL,
                            output TEXT,
                            exit_code INTEGER,
                            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            duration REAL)''')
            
            try:
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_logs_user_time 
                               ON terminal_logs(username, time DESC)''')
            except:
                pass
        
        # Server logs table
        with sqlite3.connect(LOG_DB) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS server_logs 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            level TEXT NOT NULL,
                            message TEXT NOT NULL,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        print("✅ Databases initialized successfully")
        
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")
        traceback.print_exc()

init_dbs()

# Logging function
def server_log(level, message):
    try:
        with sqlite3.connect(LOG_DB) as conn:
            conn.execute("INSERT INTO server_logs (level, message) VALUES (?, ?)",
                        (level, message))
    except:
        pass
    
    print(f"[{level.upper()}] {message}")

# Enhanced safe command execution
ALLOWED_COMMANDS = {
    'ls', 'pwd', 'cd', 'cat', 'echo', 'python', 'python3',
    'pip', 'pip3', 'git', 'curl', 'wget', 'mkdir', 'rmdir',
    'cp', 'mv', 'find', 'grep', 'ps', 'whoami', 'date', 'uname',
    'touch', 'head', 'tail', 'wc', 'sort', 'uniq', 'tree',
    'df', 'du', 'free', 'top', 'htop', 'nano', 'vim', 'vi'
}

def is_safe_command(command):
    """Enhanced command validation"""
    if not command or len(command.strip()) == 0:
        return False
    
    cmd = command.strip()
    
    # Dangerous patterns
    dangerous_patterns = [
        r'rm\s+-(rf|fr|r|f)', r'dd\s+if=', r'mkfs', r'chmod\s+[0-7]{3,4}',
        r'>\s*/dev/', r'>>\s*/dev/', r'&\s*>\s*/dev/', r'sudo\s+',
        r'su\s+', r'passwd', r'shutdown', r'reboot', r'halt', r'poweroff',
        r'killall', r'pkill', r'kill\s+-9', r'systemctl',
        r'wget\s+.*\s+-O\s+.*\.(sh|exe|bat|cmd)', r'curl\s+.*\s+-o\s+.*\.(sh|exe|bat|cmd)',
        r'python\s+-c\s+.*(__import__|eval|exec|compile|open\(.*,\s*[\"\'][wax\+]|os\.system|subprocess)',
        r'(\$\(|`)', r'\|\s*bash\s*$', r'\|\s*sh\s*$'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False
    
    # Check for directory traversal
    if '..' in cmd or '../' in cmd:
        if not cmd.startswith('cd '):  # cd .. is allowed
            return False
    
    # Check allowed commands
    cmd_parts = cmd.split()
    if cmd_parts:
        base_cmd = cmd_parts[0]
        
        # Allow pip with specific subcommands
        if base_cmd in ['pip', 'pip3']:
            allowed_pip_commands = ['install', 'uninstall', 'list', 'show', 
                                   'freeze', 'check', 'search', 'download']
            if len(cmd_parts) > 1 and cmd_parts[1] not in allowed_pip_commands:
                return False
            return True
        
        # Allow python commands
        elif base_cmd in ['python', 'python3']:
            # Disallow dangerous python options
            dangerous_python = ['-c', '--command', '-m', '--module']
            for i, part in enumerate(cmd_parts):
                if part in dangerous_python and i + 1 < len(cmd_parts):
                    next_part = cmd_parts[i + 1].lower()
                    if any(danger in next_part for danger in ['import os', 'import sys', 'eval', 'exec']):
                        return False
            return True
        
        # Check other allowed commands
        elif base_cmd not in ALLOWED_COMMANDS:
            # Check if it's a system path (like /bin/ls)
            if os.path.exists(base_cmd) and os.access(base_cmd, os.X_OK):
                # Only allow binaries from safe directories
                safe_dirs = ['/bin', '/usr/bin', '/usr/local/bin']
                if any(base_cmd.startswith(d) for d in safe_dirs):
                    return True
            return False
    
    return True

# Enhanced filename validation
def is_safe_filename(filename):
    """Validate filename for security"""
    if not filename or len(filename) > 255:
        return False
    
    # Only allow safe characters
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_. -]*[a-zA-Z0-9]$', filename):
        return False
    
    # Prevent directory traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Prevent dangerous extensions
    dangerous_ext = ['.sh', '.exe', '.bat', '.cmd', '.js', '.php', 
                     '.pl', '.rb', '.pyc', '.so', '.dll']
    for ext in dangerous_ext:
        if filename.lower().endswith(ext):
            return False
    
    # Block reserved filenames
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3',
                     'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                     'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6',
                     'LPT7', 'LPT8', 'LPT9']
    if filename.upper() in reserved_names:
        return False
    
    return True

# File extension validation
def has_allowed_extension(filename):
    allowed = SETTINGS['allowed_extensions']
    if not allowed:  # If empty list, allow all
        return True
    return any(filename.lower().endswith(ext) for ext in allowed)

# --- Enhanced HTML Template ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber 20 UN</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root {
            --bg: #020617;
            --purple: #8b5cf6;
            --blue: #3b82f6;
            --cyan: #06b6d4;
            --text: #f8fafc;
            --glass: rgba(15, 23, 42, 0.6);
            --border: rgba(255, 255, 255, 0.1);
            --success: #10b981;
            --error: #ef4444;
            --warning: #f59e0b;
        }
        * { 
            box-sizing: border-box; 
            margin: 0; 
            padding: 0; 
        }
        body {
            font-family: 'Poppins', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }
        @media (min-width: 1024px) {
            .container {
                grid-template-columns: 1fr 1fr;
            }
        }
        .card {
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .header {
            grid-column: 1 / -1;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }
        .logo-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .cyber-logo {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--purple), var(--blue));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(139, 92, 246, 0.5);
            animation: float 3s ease-in-out infinite;
        }
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        .logo-text {
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(to right, var(--purple), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-box {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 8px 16px;
            border-radius: 50px;
            color: var(--success);
            font-size: 14px;
            font-weight: 600;
        }
        .editor-container {
            grid-column: 1;
        }
        .terminal-container {
            grid-column: 2;
        }
        @media (max-width: 1023px) {
            .editor-container,
            .terminal-container {
                grid-column: 1;
            }
        }
        h3 {
            margin: 0 0 20px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 18px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--cyan);
            font-size: 14px;
        }
        input, textarea, select {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 15px;
            border-radius: 12px;
            width: 100%;
            font-family: 'Fira Code', monospace;
            font-size: 14px;
            outline: none;
            transition: all 0.3s ease;
        }
        input:focus, textarea:focus, select:focus {
            border-color: var(--purple);
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }
        textarea#code {
            min-height: 250px;
            resize: vertical;
        }
        .btn-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .btn {
            background: linear-gradient(45deg, var(--purple), var(--blue));
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            font-size: 14px;
            transition: all 0.3s ease;
            flex: 1;
            min-width: 120px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(139, 92, 246, 0.4);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--border);
        }
        .btn-danger {
            background: linear-gradient(45deg, #ef4444, #dc2626);
        }
        #terminal {
            background: #000;
            color: #a5f3fc;
            height: 350px;
            overflow-y: auto;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Fira Code', monospace;
            font-size: 13px;
            border: 1px solid var(--border);
            line-height: 1.5;
            margin-bottom: 20px;
        }
        .log-line {
            border-left: 3px solid var(--purple);
            padding-left: 12px;
            margin-bottom: 8px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .cmd-line { color: var(--success); }
        .error-line { color: var(--error); }
        .info-line { color: var(--cyan); }
        .warning-line { color: var(--warning); }
        .output-line { color: #d1d5db; }
        .command-input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        #cmd {
            flex: 1;
            margin: 0;
        }
        .quick-commands {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 15px;
        }
        .quick-cmd-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 6px 12px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 11px;
            font-family: 'Fira Code', monospace;
            transition: all 0.3s ease;
        }
        .quick-cmd-btn:hover {
            background: rgba(139, 92, 246, 0.2);
            border-color: var(--purple);
        }
        .file-manager {
            margin-top: 20px;
        }
        .file-list {
            max-height: 200px;
            overflow-y: auto;
            margin: 15px 0;
            padding: 15px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
        }
        .file-item {
            padding: 8px 12px;
            margin: 5px 0;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s ease;
        }
        .file-item:hover {
            background: rgba(139, 92, 246, 0.1);
        }
        .file-actions {
            display: flex;
            gap: 8px;
        }
        .action-btn {
            background: none;
            border: none;
            color: var(--cyan);
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            transition: all 0.3s ease;
        }
        .action-btn:hover {
            background: rgba(6, 182, 212, 0.2);
        }
        .logout-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
            padding: 10px 20px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 1000;
        }
        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.3);
        }
        .terminal-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .terminal-info {
            font-size: 12px;
            color: var(--cyan);
            opacity: 0.8;
        }
        .clear-btn {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        }
        .clear-btn:hover {
            background: rgba(239, 68, 68, 0.3);
        }
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            text-align: center;
        }
        .login-logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
        }
        .login-form input {
            margin-bottom: 20px;
        }
        .server-info {
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .info-card {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .info-card .value {
            font-size: 24px;
            font-weight: 700;
            color: var(--cyan);
            margin-bottom: 5px;
        }
        .info-card .label {
            font-size: 12px;
            color: var(--text);
            opacity: 0.7;
        }
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .card { padding: 20px; }
            #terminal { height: 300px; }
            .btn { min-width: 100px; }
        }
        .notifications {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            max-width: 300px;
        }
        .notification {
            background: var(--glass);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            backdrop-filter: blur(10px);
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .notification.success { border-left: 4px solid var(--success); }
        .notification.error { border-left: 4px solid var(--error); }
        .notification.warning { border-left: 4px solid var(--warning); }
        .notification.info { border-left: 4px solid var(--cyan); }
        .suggestions {
            position: absolute;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            width: 100%;
            display: none;
        }
        .suggestion-item {
            padding: 10px;
            cursor: pointer;
            border-bottom: 1px solid var(--border);
        }
        .suggestion-item:hover {
            background: rgba(139, 92, 246, 0.1);
        }
        .suggestion-item:last-child {
            border-bottom: none;
        }
        .typing-indicator {
            display: none;
            color: var(--cyan);
            font-size: 12px;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    {% if not logged_in %}
    <div class="container login-container">
        <div class="card">
            <div class="cyber-logo login-logo">
                <i data-lucide="terminal" color="white" width="32" height="32"></i>
            </div>
            <h2 style="margin-bottom: 30px;">Cyber 20 UN</h2>
            <form method="POST" action="/login" class="login-form">
                <input type="text" name="username" placeholder="Username" required autocomplete="off">
                <input type="password" name="password" placeholder="Password" required autocomplete="off">
                <button type="submit" class="btn" style="width: 100%;">
                    <i data-lucide="log-in" width="18" height="18"></i>
                    Initialize Session
                </button>
            </form>
            <p style="margin-top: 20px; font-size: 13px; color: var(--cyan); opacity: 0.8;">
                Create new account or login with existing credentials
            </p>
        </div>
    </div>
    {% else %}
    <div class="container">
        <div class="header">
            <div class="logo-container">
                <div class="cyber-logo">
                    <i data-lucide="terminal" color="white" width="24" height="24"></i>
                </div>
                <div>
                    <div class="logo-text">Cyber 20 UN</div>
                    <div style="font-size: 12px; color: var(--cyan);">Welcome, {{ username }} • {{ session_id }}</div>
                </div>
            </div>
            <div id="statusIndicator" class="status-box">
                <i data-lucide="circle" width="12" height="12"></i>
                CONNECTING...
            </div>
        </div>

        <div class="card editor-container">
            <h3><i data-lucide="file-code" width="18" height="18"></i> Code Editor</h3>
            
            <div class="form-group">
                <label for="filename"><i data-lucide="file-text" width="14" height="14"></i> Filename</label>
                <input type="text" id="filename" placeholder="main.py" value="main.py">
            </div>
            
            <div class="form-group">
                <label for="code"><i data-lucide="code" width="14" height="14"></i> Code</label>
                <textarea id="code" placeholder="# Write your Python code here...">print("Hello, Cyber 20 UN!")
print(f"Python {sys.version}")
print("Server is running!")</textarea>
            </div>
            
            <div class="btn-group">
                <button onclick="runCode()" class="btn">
                    <i data-lucide="play-circle" width="16" height="16"></i>
                    Run
                </button>
                <button onclick="saveCode()" class="btn btn-secondary">
                    <i data-lucide="save" width="16" height="16"></i>
                    Save
                </button>
                <button onclick="clearEditor()" class="btn btn-secondary">
                    <i data-lucide="trash-2" width="16" height="16"></i>
                    Clear
                </button>
            </div>
            
            <div class="file-manager">
                <h4 style="margin: 20px 0 10px 0;">
                    <i data-lucide="folder" width="16" height="16"></i>
                    File Manager
                </h4>
                <div id="fileList" class="file-list">
                    <!-- Files will be loaded here -->
                </div>
            </div>
        </div>

        <div class="card terminal-container">
            <div class="terminal-controls">
                <h3 style="margin: 0;"><i data-lucide="terminal-square" width="18" height="18"></i> Live Terminal</h3>
                <div class="terminal-info">
                    <span id="connectionInfo">Connected via polling</span>
                </div>
                <button onclick="clearTerminal()" class="clear-btn">
                    <i data-lucide="x-circle" width="14" height="14"></i>
                    Clear
                </button>
            </div>
            
            <div id="terminal"></div>
            
            <div class="quick-commands">
                <button class="quick-cmd-btn" onclick="runQuickCmd('ls -la')">ls -la</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('pwd')">pwd</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('python --version')">python --version</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('pip list')">pip list</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('whoami')">whoami</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('date')">date</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('df -h')">df -h</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('free -h')">free -h</button>
            </div>
            
            <div class="form-group">
                <label for="cmd"><i data-lucide="command" width="14" height="14"></i> Command Input</label>
                <div class="command-input-group">
                    <input type="text" id="cmd" placeholder="Enter command..." onkeypress="handleKeyPress(event)" autocomplete="off">
                    <button onclick="sendCommand()" class="btn" style="width: auto; min-width: 60px;">
                        <i data-lucide="chevron-right" width="16" height="16"></i>
                    </button>
                </div>
                <div id="suggestions" class="suggestions"></div>
                <div id="typingIndicator" class="typing-indicator">
                    <i data-lucide="loader" width="12" height="12" class="spin"></i>
                    Processing...
                </div>
            </div>
            
            <div style="font-size: 11px; color: var(--cyan); opacity: 0.7; margin-top: 10px;">
                <i data-lucide="shield" width="11" height="11"></i>
                Safe mode enabled • Commands logged • Max timeout: {{ settings.command_timeout }}s
            </div>
        </div>

        <div class="server-info">
            <div class="info-card">
                <div class="value" id="userCount">0</div>
                <div class="label">Active Users</div>
            </div>
            <div class="info-card">
                <div class="value" id="fileCount">0</div>
                <div class="label">Your Files</div>
            </div>
            <div class="info-card">
                <div class="value" id="commandCount">0</div>
                <div class="label">Commands Executed</div>
            </div>
            <div class="info-card">
                <div class="value" id="uptime">0s</div>
                <div class="label">Server Uptime</div>
            </div>
        </div>
        
        <button class="logout-btn" onclick="logout()">
            <i data-lucide="log-out" width="14" height="14"></i>
            Logout
        </button>
    </div>
    
    <div class="notifications" id="notifications"></div>
    {% endif %}

    <script>
        // Initialize icons
        lucide.createIcons();
        
        // Add spin animation for loader
        const style = document.createElement('style');
        style.textContent = `
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            .spin {
                animation: spin 1s linear infinite;
            }
        `;
        document.head.appendChild(style);
        
        // Initialize variables
        let commandHistory = [];
        let historyIndex = -1;
        let isProcessing = false;
        const sessionId = '{{ session_id }}';
        
        // Socket.IO connection - Polling only for Render.com
        const socket = io({
            transports: ['polling'],
            reconnection: true,
            reconnectionAttempts: 10,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 60000
        });
        
        // Connection management
        socket.on('connect', () => {
            console.log('Connected to server via polling');
            updateStatus('CONNECTED 🟢', 'success');
            addLog('Connected to Cyber 20 UN server', 'info');
            document.getElementById('connectionInfo').textContent = 'Connected via polling';
            loadUserFiles();
            updateServerStats();
            
            // Request session restore
            socket.emit('restore_session');
            
            // Notify user
            showNotification('Connected successfully!', 'success');
        });
        
        socket.on('disconnect', (reason) => {
            console.log('Disconnected:', reason);
            updateStatus('DISCONNECTED 🔴', 'error');
            addLog(`Disconnected: ${reason}`, 'warning');
            document.getElementById('connectionInfo').textContent = 'Disconnected';
            showNotification('Disconnected from server', 'warning');
        });
        
        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            updateStatus('ERROR ⚠️', 'error');
            addLog(`Connection error: ${error.message}`, 'error');
            showNotification('Connection error', 'error');
        });
        
        socket.on('reconnect', (attemptNumber) => {
            console.log('Reconnected after', attemptNumber, 'attempts');
            updateStatus('RECONNECTED 🔄', 'success');
            addLog(`Reconnected (attempt ${attemptNumber})`, 'info');
            showNotification('Reconnected to server', 'success');
        });
        
        socket.on('reconnecting', (attemptNumber) => {
            console.log('Reconnecting attempt', attemptNumber);
            updateStatus('RECONNECTING...', 'warning');
        });
        
        // Terminal logs
        socket.on('log', (data) => {
            addLog(data.msg, data.type || 'output');
            hideTypingIndicator();
            isProcessing = false;
        });
        
        socket.on('command_start', () => {
            showTypingIndicator();
            isProcessing = true;
        });
        
        socket.on('command_end', (data) => {
            hideTypingIndicator();
            isProcessing = false;
            if (data && data.success) {
                addLog(`✅ Command completed (${data.duration}s)`, 'info');
            }
        });
        
        // Session restore
        socket.on('session_restore', (data) => {
            if (data.last_file) {
                document.getElementById('filename').value = data.last_file.filename;
                document.getElementById('code').value = data.last_file.code;
                addLog(`📁 Restored: ${data.last_file.filename}`, 'info');
                showNotification('Previous session restored', 'success');
            }
        });
        
        // File list update
        socket.on('file_list', (data) => {
            updateFileList(data.files);
            document.getElementById('fileCount').textContent = data.files.length;
        });
        
        // Server stats update
        socket.on('server_stats', (data) => {
            updateServerStatsDisplay(data);
        });
        
        // Command suggestions
        socket.on('command_suggestions', (data) => {
            showSuggestions(data.suggestions);
        });
        
        // Helper functions
        function updateStatus(text, type) {
            const statusEl = document.getElementById('statusIndicator');
            if (!statusEl) return;
            
            statusEl.innerHTML = `<i data-lucide="circle" width="12" height="12"></i> ${text}`;
            
            if (type === 'success') {
                statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                statusEl.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                statusEl.style.color = 'var(--success)';
            } else if (type === 'error') {
                statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
                statusEl.style.borderColor = 'rgba(239, 68, 68, 0.3)';
                statusEl.style.color = 'var(--error)';
            } else if (type === 'warning') {
                statusEl.style.background = 'rgba(245, 158, 11, 0.15)';
                statusEl.style.borderColor = 'rgba(245, 158, 11, 0.3)';
                statusEl.style.color = 'var(--warning)';
            }
            
            lucide.createIcons();
        }
        
        function addLog(message, type = 'output') {
            const terminal = document.getElementById('terminal');
            if (!terminal) return;
            
            const line = document.createElement('div');
            line.className = 'log-line';
            
            let icon = '';
            let className = '';
            
            switch(type) {
                case 'cmd':
                    className = 'cmd-line';
                    icon = '<span style="color: var(--success);">$</span> ';
                    break;
                case 'error':
                    className = 'error-line';
                    icon = '<span style="color: var(--error);">✗</span> ';
                    break;
                case 'info':
                    className = 'info-line';
                    icon = '<span style="color: var(--cyan);">ℹ</span> ';
                    break;
                case 'warning':
                    className = 'warning-line';
                    icon = '<span style="color: var(--warning);">⚠</span> ';
                    break;
                case 'success':
                    className = 'cmd-line';
                    icon = '<span style="color: var(--success);">✓</span> ';
                    break;
                default:
                    className = 'output-line';
                    icon = '> ';
            }
            
            line.classList.add(className);
            line.innerHTML = icon + message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function showNotification(message, type = 'info') {
            const notifications = document.getElementById('notifications');
            if (!notifications) return;
            
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <i data-lucide="${getNotificationIcon(type)}" width="16" height="16"></i>
                    <div>${message}</div>
                </div>
            `;
            
            notifications.appendChild(notification);
            lucide.createIcons();
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }
        
        function getNotificationIcon(type) {
            switch(type) {
                case 'success': return 'check-circle';
                case 'error': return 'alert-circle';
                case 'warning': return 'alert-triangle';
                default: return 'info';
            }
        }
        
        function showTypingIndicator() {
            const indicator = document.getElementById('typingIndicator');
            if (indicator) {
                indicator.style.display = 'block';
            }
        }
        
        function hideTypingIndicator() {
            const indicator = document.getElementById('typingIndicator');
            if (indicator) {
                indicator.style.display = 'none';
            }
        }
        
        function showSuggestions(suggestions) {
            const suggestionsEl = document.getElementById('suggestions');
            if (!suggestionsEl || !suggestions.length) {
                suggestionsEl.style.display = 'none';
                return;
            }
            
            suggestionsEl.innerHTML = suggestions.map(cmd => `
                <div class="suggestion-item" onclick="useSuggestion('${cmd}')">
                    ${cmd}
                </div>
            `).join('');
            
            suggestionsEl.style.display = 'block';
        }
        
        function useSuggestion(cmd) {
            document.getElementById('cmd').value = cmd;
            document.getElementById('suggestions').style.display = 'none';
            document.getElementById('cmd').focus();
        }
        
        function loadUserFiles() {
            socket.emit('get_files');
        }
        
        function updateFileList(files) {
            const fileListEl = document.getElementById('fileList');
            if (!fileListEl) return;
            
            if (!files || files.length === 0) {
                fileListEl.innerHTML = '<div style="text-align: center; color: var(--cyan); padding: 20px; opacity: 0.7;">No files yet</div>';
                return;
            }
            
            fileListEl.innerHTML = files.map(file => `
                <div class="file-item" data-filename="${file.filename}">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="${getFileIcon(file.filename)}" width="14" height="14"></i>
                        <div>
                            <div style="font-weight: 500;">${file.filename}</div>
                            <div style="font-size: 11px; color: var(--cyan); opacity: 0.7;">
                                ${formatDate(file.time)} • ${formatFileSize(file.file_size)}
                            </div>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button onclick="loadFile('${file.filename}')" class="action-btn" title="Load">
                            <i data-lucide="folder-open" width="14" height="14"></i>
                        </button>
                        <button onclick="deleteFile('${file.filename}')" class="action-btn" title="Delete">
                            <i data-lucide="trash-2" width="14" height="14"></i>
                        </button>
                        <button onclick="downloadFile('${file.filename}')" class="action-btn" title="Download">
                            <i data-lucide="download" width="14" height="14"></i>
                        </button>
                    </div>
                </div>
            `).join('');
            
            lucide.createIcons();
        }
        
        function getFileIcon(filename) {
            if (filename.endsWith('.py')) return 'file-code';
            if (filename.endsWith('.txt')) return 'file-text';
            if (filename.endsWith('.md')) return 'file-text';
            if (filename.endsWith('.json')) return 'file-json';
            if (filename.endsWith('.html')) return 'file-code-2';
            if (filename.endsWith('.css')) return 'file-css';
            if (filename.endsWith('.js')) return 'file-js';
            return 'file';
        }
        
        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0 || bytes === undefined) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function updateServerStats() {
            socket.emit('get_server_stats');
        }
        
        function updateServerStatsDisplay(data) {
            if (data.user_count !== undefined) {
                document.getElementById('userCount').textContent = data.user_count;
            }
            if (data.file_count !== undefined) {
                document.getElementById('fileCount').textContent = data.file_count;
            }
            if (data.command_count !== undefined) {
                document.getElementById('commandCount').textContent = data.command_count;
            }
            if (data.uptime !== undefined) {
                document.getElementById('uptime').textContent = data.uptime;
            }
        }
        
        // File operations
        function loadFile(filename) {
            fetch(`/api/file/${encodeURIComponent(filename)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('filename').value = data.filename;
                        document.getElementById('code').value = data.code;
                        addLog(`📁 Loaded: ${data.filename}`, 'info');
                        showNotification('File loaded successfully', 'success');
                    } else {
                        addLog(`Error: ${data.error}`, 'error');
                        showNotification(data.error, 'error');
                    }
                })
                .catch(error => {
                    addLog(`Error loading file: ${error}`, 'error');
                    showNotification('Failed to load file', 'error');
                });
        }
        
        function deleteFile(filename) {
            if (!confirm(`Are you sure you want to delete "${filename}"?`)) return;
            
            fetch(`/api/file/${encodeURIComponent(filename)}`, {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    addLog(`🗑️ Deleted: ${filename}`, 'info');
                    showNotification('File deleted successfully', 'success');
                    loadUserFiles();
                } else {
                    addLog(`Error: ${data.error}`, 'error');
                    showNotification(data.error, 'error');
                }
            })
            .catch(error => {
                addLog(`Error deleting file: ${error}`, 'error');
                showNotification('Failed to delete file', 'error');
            });
        }
        
        function downloadFile(filename) {
            window.open(`/api/file/${encodeURIComponent(filename)}/download`, '_blank');
        }
        
        // Code operations
        function runCode() {
            const filename = document.getElementById('filename').value.trim();
            const code = document.getElementById('code').value;
            
            if (!filename) {
                showNotification('Please enter a filename', 'error');
                return;
            }
            
            if (!code) {
                showNotification('Please enter some code', 'error');
                return;
            }
            
            socket.emit('save_and_run', {filename: filename, code: code});
            addLog(`🚀 Running ${filename}...`, 'cmd');
            showNotification('Running code...', 'info');
        }
        
        function saveCode() {
            const filename = document.getElementById('filename').value.trim();
            const code = document.getElementById('code').value;
            
            if (!filename) {
                showNotification('Please enter a filename', 'error');
                return;
            }
            
            if (!code) {
                showNotification('Please enter some code', 'error');
                return;
            }
            
            socket.emit('save_code', {filename: filename, code: code});
            showNotification('Saving file...', 'info');
        }
        
        function clearEditor() {
            if (confirm('Clear the editor? This will not delete saved files.')) {
                document.getElementById('code').value = '';
                showNotification('Editor cleared', 'info');
            }
        }
        
        // Terminal operations
        function sendCommand() {
            if (isProcessing) {
                showNotification('Please wait for current command to finish', 'warning');
                return;
            }
            
            const cmd = document.getElementById('cmd').value.trim();
            if (!cmd) {
                showNotification('Please enter a command', 'error');
                return;
            }
            
            socket.emit('execute_command', {command: cmd});
            addLog(cmd, 'cmd');
            
            // Add to history
            if (!commandHistory.includes(cmd)) {
                commandHistory.unshift(cmd);
                if (commandHistory.length > 50) commandHistory.pop();
            }
            
            document.getElementById('cmd').value = '';
            historyIndex = -1;
            document.getElementById('suggestions').style.display = 'none';
        }
        
        function runQuickCmd(cmd) {
            document.getElementById('cmd').value = cmd;
            sendCommand();
        }
        
        function clearTerminal() {
            const terminal = document.getElementById('terminal');
            if (terminal) {
                terminal.innerHTML = '';
                showNotification('Terminal cleared', 'info');
            }
        }
        
        function handleKeyPress(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                sendCommand();
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                if (commandHistory.length > 0) {
                    historyIndex = Math.min(historyIndex + 1, commandHistory.length - 1);
                    document.getElementById('cmd').value = commandHistory[historyIndex];
                }
            } else if (event.key === 'ArrowDown') {
                event.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    document.getElementById('cmd').value = commandHistory[historyIndex];
                } else {
                    historyIndex = -1;
                    document.getElementById('cmd').value = '';
                }
            } else if (event.key === 'Tab') {
                event.preventDefault();
                const current = document.getElementById('cmd').value;
                if (current.trim()) {
                    socket.emit('get_suggestions', {partial: current});
                }
            }
        }
        
        // Hide suggestions when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#suggestions') && !e.target.closest('#cmd')) {
                document.getElementById('suggestions').style.display = 'none';
            }
        });
        
        // Logout
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                window.location.href = '/logout';
            }
        }
        
        // Request session restore on page load
        window.addEventListener('load', () => {
            // Set up periodic stats update
            setInterval(updateServerStats, 30000);
            
            // Focus on command input
            document.getElementById('cmd')?.focus();
            
            // Add welcome message
            setTimeout(() => {
                addLog('Cyber 20 UN Terminal Ready', 'info');
                addLog('Type "help" for available commands', 'info');
            }, 1000);
        });
    </script>
</body>
</html>
"""

# Ghost Mode Template
GHOST_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Ghost Mode - Cyber 20 UN</title>
    <style>
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.1;
            z-index: -1;
        }
        .container {
            max-width: 800px;
            margin: 100px auto;
            padding: 30px;
            border: 1px solid #0f0;
            background: rgba(0, 255, 0, 0.05);
            box-shadow: 0 0 50px rgba(0, 255, 0, 0.3);
        }
        h1 {
            text-align: center;
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
            animation: glow 2s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 10px #0f0; }
            to { text-shadow: 0 0 20px #0f0, 0 0 30px #0f0; }
        }
        .status-item {
            margin: 15px 0;
            padding: 10px;
            border-left: 3px solid #0f0;
            background: rgba(0, 255, 0, 0.1);
        }
        .label {
            color: #0f0;
            font-weight: bold;
        }
        .value {
            color: #fff;
            margin-left: 10px;
        }
        .warning {
            color: #ff0;
            text-align: center;
            margin-top: 30px;
            font-size: 14px;
        }
        .ascii-art {
            text-align: center;
            font-size: 12px;
            color: #0f0;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="ascii-art">
<pre>
  ___  _   _  ___  ___  _  _   __   __  
 / __|| | | ||_ _|/ __|| || |  \\ \\ / /  
| (__ | |_| | | | \\__ \\| __ |   \\ V /   
 \\___| \\___/ |___||___/|_||_|    \\_/    
</pre>
        </div>
        
        <h1>👻 GHOST MODE ACTIVATED</h1>
        
        <div class="status-item">
            <span class="label">• ACCESS LEVEL:</span>
            <span class="value">RESTRICTED</span>
        </div>
        
        <div class="status-item">
            <span class="label">• CONNECTION:</span>
            <span class="value">ENCRYPTED [AES-256]</span>
        </div>
        
        <div class="status-item">
            <span class="label">• SERVER STATUS:</span>
            <span class="value">🟢 OPERATIONAL</span>
        </div>
        
        <div class="status-item">
            <span class="label">• ACTIVE USERS:</span>
            <span class="value">{{ user_count }}</span>
        </div>
        
        <div class="status-item">
            <span class="label">• UPTIME:</span>
            <span class="value">{{ uptime }}</span>
        </div>
        
        <div class="warning">
            ⚠️ WARNING: UNAUTHORIZED ACCESS IS PROHIBITED
        </div>
        
        <div style="text-align: center; margin-top: 30px; font-size: 12px; color: #0f0;">
            Ghost Key: {{ ghost_key }}
        </div>
    </div>
    
    <script>
        // Matrix rain effect
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.className = 'matrix-bg';
        document.body.appendChild(canvas);
        
        const chars = "01";
        const fontSize = 14;
        let columns;
        
        function initMatrix() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            columns = canvas.width / fontSize;
        }
        
        const drops = [];
        function setupDrops() {
            drops.length = 0;
            for (let i = 0; i < columns; i++) {
                drops[i] = 1;
            }
        }
        
        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';
            
            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        
        window.addEventListener('resize', initMatrix);
        initMatrix();
        setupDrops();
        setInterval(drawMatrix, 50);
    </script>
</body>
</html>
"""

# Access Mode Template
ACCESS_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Access Portal - Cyber 20 UN</title>
    <style>
        body {
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
            font-family: 'Arial', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .portal {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 40px;
            border-radius: 25px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            text-align: center;
            max-width: 600px;
            width: 100%;
            animation: fadeIn 1s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            color: #fff;
            margin-bottom: 30px;
            font-size: 36px;
        }
        .key-box {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(139, 92, 246, 0.5);
            padding: 20px;
            border-radius: 15px;
            margin: 20px 0;
            text-align: left;
        }
        .key-label {
            color: #8b5cf6;
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .key-value {
            color: #fff;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            font-size: 13px;
            background: rgba(0, 0, 0, 0.5);
            padding: 10px;
            border-radius: 8px;
            margin-top: 5px;
        }
        .url-box {
            margin: 15px 0;
        }
        .url {
            color: #06b6d4;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .url:hover {
            text-decoration: underline;
        }
        .btn-group {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
            flex-wrap: wrap;
        }
        .btn {
            background: linear-gradient(45deg, #8b5cf6, #3b82f6);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            min-width: 150px;
        }
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(139, 92, 246, 0.4);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 8px 16px;
            border-radius: 50px;
            color: #10b981;
            font-size: 14px;
            margin-bottom: 20px;
        }
        .info-text {
            color: #a5f3fc;
            font-size: 14px;
            margin: 20px 0;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="portal">
        <h1>🔐 CYBER 20 UN ACCESS PORTAL</h1>
        
        <div class="status-indicator">
            <span>🟢 SERVER ONLINE</span>
        </div>
        
        <div class="info-text">
            Welcome to the Cyber 20 UN access portal. Use the keys below to access different interfaces.
        </div>
        
        <div class="key-box">
            <div class="key-label">Server Key:</div>
            <div class="key-value">{{ server_key }}</div>
            <div class="url-box">
                <a href="/?key={{ server_key }}" class="url">Access Main Interface</a>
            </div>
        </div>
        
        <div class="key-box">
            <div class="key-label">Access Key:</div>
            <div class="key-value">{{ access_key }}</div>
            <div class="url-box">
                <a href="/access/{{ access_key }}" class="url">Access Portal (Current Page)</a>
            </div>
        </div>
        
        <div class="key-box">
            <div class="key-label">Ghost Key:</div>
            <div class="key-value">{{ ghost_key }}</div>
            <div class="url-box">
                <a href="/ghost/{{ ghost_key }}" class="url">Access Ghost Mode</a>
            </div>
        </div>
        
        <div class="info-text">
            Server URL: <a href="{{ server_url }}" class="url">{{ server_url }}</a><br>
            Server Status: 🟢 Operational | Users: {{ user_count }} | Files: {{ file_count }}
        </div>
        
        <div class="btn-group">
            <a href="/?key={{ server_key }}" class="btn">🚀 Main Interface</a>
            <a href="/ghost/{{ ghost_key }}" class="btn btn-secondary">👻 Ghost Mode</a>
            <a href="/status" class="btn btn-secondary">📊 Server Status</a>
        </div>
    </div>
</body>
</html>
"""

# --- Server Routes & Logic ---

@app.route('/')
def index():
    key = request.args.get('key')
    if key == ACCESS_KEYS['server_key']:
        session['user'] = 'admin'
        session.permanent = True
        session['session_id'] = secrets.token_hex(8)
        return render_template_string(HTML_TEMPLATE, logged_in=True, username='admin', 
                                     session_id=session['session_id'], settings=SETTINGS)
    
    if 'user' not in session:
        return render_template_string(HTML_TEMPLATE, logged_in=False)
    
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(8)
    
    return render_template_string(HTML_TEMPLATE, logged_in=True, username=session.get('user'),
                                 session_id=session['session_id'], settings=SETTINGS)

@app.route('/access/<key>')
def access_mode(key):
    if key == ACCESS_KEYS['access_key']:
        try:
            with sqlite3.connect(USER_DB) as conn:
                user_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
                file_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        except:
            user_count = 0
            file_count = 0
        
        return render_template_string(ACCESS_TEMPLATE,
                                    server_url=request.host_url,
                                    server_key=ACCESS_KEYS['server_key'],
                                    access_key=ACCESS_KEYS['access_key'],
                                    ghost_key=ACCESS_KEYS['ghost_key'],
                                    user_count=user_count,
                                    file_count=file_count)
    return "Invalid Access Key", 403

@app.route('/ghost/<key>')
def ghost_mode(key):
    if key == ACCESS_KEYS['ghost_key']:
        try:
            with sqlite3.connect(USER_DB) as conn:
                user_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
        except:
            user_count = 0
        
        uptime_seconds = int(time.time() - app_start_time)
        uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
        
        return render_template_string(GHOST_TEMPLATE,
                                     user_count=user_count,
                                     uptime=uptime_str,
                                     ghost_key=key[:8] + "..." + key[-8:])
    return "Invalid Ghost Key", 403

@app.route('/status')
def status():
    try:
        with sqlite3.connect(USER_DB) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
            file_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            active_sessions = conn.execute("SELECT COUNT(DISTINCT username) FROM terminal_logs WHERE time > datetime('now', '-1 hour')").fetchone()[0]
        
        with sqlite3.connect(LOG_DB) as conn:
            cmd_count = conn.execute("SELECT COUNT(*) FROM terminal_logs").fetchone()[0]
            last_cmd = conn.execute("SELECT command, time FROM terminal_logs ORDER BY time DESC LIMIT 1").fetchone()
            error_count = conn.execute("SELECT COUNT(*) FROM terminal_logs WHERE exit_code != 0").fetchone()[0]
    except:
        user_count = 0
        file_count = 0
        active_sessions = 0
        cmd_count = 0
        last_cmd = None
        error_count = 0
    
    uptime_seconds = int(time.time() - app_start_time)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
    
    return jsonify({
        'status': 'online',
        'server': 'Cyber 20 UN',
        'version': '2.1.0',
        'users': {
            'total': user_count,
            'active_sessions': active_sessions
        },
        'files': file_count,
        'commands': {
            'total': cmd_count,
            'errors': error_count,
            'success_rate': f"{((cmd_count - error_count) / cmd_count * 100):.1f}%" if cmd_count > 0 else "100%"
        },
        'system': {
            'uptime': uptime_str,
            'uptime_seconds': uptime_seconds,
            'timestamp': datetime.now().isoformat(),
            'platform': sys.platform,
            'python_version': sys.version.split()[0]
        },
        'last_command': last_cmd[0] if last_cmd else None,
        'last_command_time': last_cmd[1] if last_cmd else None,
        'access_keys': {
            'server': ACCESS_KEYS['server_key'][:8] + "...",
            'access': ACCESS_KEYS['access_key'][:8] + "...",
            'ghost': ACCESS_KEYS['ghost_key'][:8] + "..."
        }
    })

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username', '').strip()
    p = request.form.get('password', '').strip()
    
    if not u or not p:
        return redirect(url_for('index'))
    
    if len(u) > 50 or len(p) > 100:
        return "Invalid credentials", 401
    
    if not re.match(r'^[a-zA-Z0-9_.-]+$', u):
        return "Invalid username format", 401
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            user = conn.execute("SELECT id, username, password, is_active FROM users WHERE username=?", (u,)).fetchone()
            
            if not user:
                # Create new user
                hashed_pwd = hash_password(p)
                try:
                    conn.execute("INSERT INTO users (username, password, last_login) VALUES (?,?,?)",
                                (u, hashed_pwd, datetime.now().isoformat()))
                    server_log('info', f'New user created: {u}')
                except sqlite3.IntegrityError:
                    return "Username already exists", 409
                except Exception as e:
                    server_log('error', f'User creation error: {e}')
                    return "Server error", 500
            else:
                # Verify existing user
                if not verify_password(p, user[2]):
                    server_log('warning', f'Failed login attempt for user: {u}')
                    return "Invalid credentials", 401
                
                if user[3] == 0:
                    server_log('warning', f'Login attempt for inactive user: {u}')
                    return "Account is inactive", 403
                
                # Update last login
                conn.execute("UPDATE users SET last_login = ? WHERE id = ?",
                            (datetime.now().isoformat(), user[0]))
                server_log('info', f'User logged in: {u}')
            
            session['user'] = u
            session['session_id'] = secrets.token_hex(8)
            session.permanent = True
            session['login_time'] = time.time()
            
    except Exception as e:
        server_log('error', f'Login error: {e}')
        traceback.print_exc()
        return "Server error", 500
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    if 'user' in session:
        server_log('info', f'User logged out: {session["user"]}')
        session.pop('user', None)
        session.pop('session_id', None)
        session.pop('login_time', None)
    return redirect(url_for('index'))

# API Routes
@app.route('/api/file/<filename>')
def get_file(filename):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = session['user']
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            file_data = conn.execute(
                "SELECT filename, code, file_size, last_modified FROM files WHERE username=? AND filename=? ORDER BY last_modified DESC LIMIT 1",
                (user, filename)
            ).fetchone()
    except Exception as e:
        server_log('error', f'File fetch error: {e}')
        return jsonify({'success': False, 'error': 'Database error'}), 500
    
    if file_data:
        return jsonify({
            'success': True,
            'filename': file_data[0],
            'code': file_data[1],
            'file_size': file_data[2],
            'last_modified': file_data[3]
        })
    
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/api/file/<filename>', methods=['DELETE'])
def delete_file(filename):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = session['user']
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            # Delete from database
            conn.execute("DELETE FROM files WHERE username=? AND filename=?", (user, filename))
            
            # Delete actual file
            user_dir = os.path.join(PROJECT_DIR, user)
            file_path = os.path.join(user_dir, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            
            server_log('info', f'File deleted: {user}/{filename}')
            return jsonify({'success': True, 'message': 'File deleted'})
    except Exception as e:
        server_log('error', f'File delete error: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<filename>/download')
def download_file(filename):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = session['user']
    user_dir = os.path.join(PROJECT_DIR, user)
    file_path = os.path.join(user_dir, filename)
    
    if os.path.exists(file_path):
        try:
            return send_from_directory(user_dir, filename, as_attachment=True)
        except Exception as e:
            server_log('error', f'File download error: {e}')
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return jsonify({'success': False, 'error': 'File not found'}), 404

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        user = session['user']
        session_id = session.get('session_id', 'unknown')
        
        emit('log', {'msg': f"✅ Connected to Cyber 20 UN", 'type': 'info'})
        emit('log', {'msg': f"👤 Welcome back, {user} (Session: {session_id})", 'type': 'info'})
        emit('log', {'msg': f"🔧 Server Version: 2.1.0 • Safe Mode: Enabled", 'type': 'info'})
        
        server_log('info', f'User connected: {user} (Session: {session_id})')
        
        # Send recent files
        try:
            with sqlite3.connect(USER_DB) as conn:
                files = conn.execute(
                    "SELECT filename, time, file_size FROM files WHERE username=? ORDER BY time DESC LIMIT 20",
                    (user,)
                ).fetchall()
                
                last_file = conn.execute(
                    "SELECT filename, code FROM files WHERE username=? ORDER BY time DESC LIMIT 1",
                    (user,)
                ).fetchone()
            
            emit('file_list', {'files': [
                {'filename': f[0], 'time': f[1], 'file_size': f[2] or 0}
                for f in files
            ]})
            
            if last_file:
                emit('session_restore', {'last_file': {
                    'filename': last_file[0],
                    'code': last_file[1]
                }})
        except Exception as e:
            emit('log', {'msg': f"⚠️ Error loading files: {str(e)}", 'type': 'warning'})
            server_log('error', f'File load error: {e}')
    else:
        emit('log', {'msg': 'Please login first', 'type': 'error'})

@socketio.on('get_files')
def handle_get_files():
    if 'user' not in session:
        return
    
    user = session['user']
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            files = conn.execute(
                "SELECT filename, time, file_size FROM files WHERE username=? ORDER BY time DESC LIMIT 50",
                (user,)
            ).fetchall()
    except Exception as e:
        server_log('error', f'Get files error: {e}')
        files = []
    
    emit('file_list', {'files': [
        {'filename': f[0], 'time': f[1], 'file_size': f[2] or 0}
        for f in files
    ]})

@socketio.on('get_server_stats')
def handle_get_stats():
    try:
        with sqlite3.connect(USER_DB) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
            
            if 'user' in session:
                user = session['user']
                file_count = conn.execute("SELECT COUNT(*) FROM files WHERE username=?", (user,)).fetchone()[0]
                command_count = conn.execute("SELECT COUNT(*) FROM terminal_logs WHERE username=?", (user,)).fetchone()[0]
            else:
                file_count = 0
                command_count = 0
        
        uptime_seconds = int(time.time() - app_start_time)
        uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
        
        emit('server_stats', {
            'user_count': user_count,
            'file_count': file_count,
            'command_count': command_count,
            'uptime': uptime_str
        })
    except Exception as e:
        server_log('error', f'Stats error: {e}')

@socketio.on('get_suggestions')
def handle_suggestions(data):
    if 'user' not in session:
        return
    
    partial = data.get('partial', '').lower()
    suggestions = []
    
    for cmd in ALLOWED_COMMANDS:
        if cmd.startswith(partial):
            suggestions.append(cmd)
    
    # Add common command patterns
    common_patterns = [
        'ls -la', 'python --version', 'pip list', 
        'git status', 'cat ', 'grep ', 'find '
    ]
    
    for pattern in common_patterns:
        if pattern.startswith(partial):
            suggestions.append(pattern)
    
    if len(suggestions) > 10:
        suggestions = suggestions[:10]
    
    emit('command_suggestions', {'suggestions': suggestions})

@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session:
        emit('log', {'msg': '❌ Please login first', 'type': 'error'})
        return
    
    user = session['user']
    cmd = data['command'].strip()
    
    if not cmd:
        emit('log', {'msg': 'Empty command', 'type': 'warning'})
        return
    
    # Security check
    if not is_safe_command(cmd):
        emit('log', {'msg': '❌ Command not allowed for security reasons', 'type': 'error'})
        emit('log', {'msg': 'Allowed commands: python, pip, git, and safe system commands', 'type': 'info'})
        server_log('warning', f'Blocked unsafe command from {user}: {cmd}')
        return
    
    server_log('info', f'Command from {user}: {cmd}')
    emit('command_start')
    
    def run_command():
        start_time = time.time()
        full_output = []
        exit_code = 0
        
        try:
            user_dir = os.path.join(PROJECT_DIR, user)
            os.makedirs(user_dir, exist_ok=True)
            
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            # Handle special commands
            if cmd.startswith('cd '):
                target_dir = cmd[3:].strip()
                if target_dir == '~' or not target_dir:
                    target_dir = user_dir
                elif not os.path.isabs(target_dir):
                    target_dir = os.path.join(user_dir, target_dir)
                
                try:
                    os.chdir(target_dir)
                    emit('log', {'msg': f'Changed directory to: {os.getcwd()}', 'type': 'info'})
                except Exception as e:
                    emit('log', {'msg': f'cd error: {str(e)}', 'type': 'error'})
                finally:
                    duration = time.time() - start_time
                    emit('command_end', {'success': True, 'duration': round(duration, 2)})
                return
            
            # Handle help command
            if cmd.lower() == 'help':
                help_text = """
Available Commands:
══════════════════
• System: ls, pwd, cd, cat, echo, grep, find, ps, whoami, date, uname
• Python: python, python3, pip, pip3
• File: touch, head, tail, wc, sort, uniq, tree
• Info: df -h, free -h, du -h
• Git: git status, git log, git clone
• Editor: Use the code editor to write and run Python files

Tips:
• Use Tab for command suggestions
• Files are saved in your personal directory
• All commands are logged for security
                """
                for line in help_text.strip().split('\n'):
                    emit('log', {'msg': line, 'type': 'info'})
                duration = time.time() - start_time
                emit('command_end', {'success': True, 'duration': round(duration, 2)})
                return
            
            # Run other commands
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=user_dir,
                env=env,
                universal_newlines=True,
                errors='replace'
            )
            
            # Set timeout
            def kill_process():
                try:
                    process.terminate()
                    process.wait(timeout=1)
                except:
                    try:
                        process.kill()
                    except:
                        pass
            
            timer = threading.Timer(SETTINGS['command_timeout'], kill_process)
            timer.start()
            
            # Read output line by line
            while True:
                if process.stdout:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        line = output.rstrip('\n')
                        emit('log', {'msg': line, 'type': 'output'})
                        full_output.append(line)
                
                # Check if we should continue
                if time.time() - start_time > SETTINGS['command_timeout']:
                    emit('log', {'msg': f'⏰ Command timeout ({SETTINGS["command_timeout"]}s)', 'type': 'error'})
                    break
            
            timer.cancel()
            exit_code = process.wait()
            
            duration = time.time() - start_time
            
            if exit_code == 0:
                emit('log', {'msg': f'✅ Command completed ({duration:.2f}s)', 'type': 'success'})
            else:
                emit('log', {'msg': f'❌ Command failed with exit code {exit_code} ({duration:.2f}s)', 'type': 'error'})
            
            emit('command_end', {'success': exit_code == 0, 'duration': round(duration, 2)})
            
            # Log to database
            try:
                with sqlite3.connect(LOG_DB) as conn:
                    conn.execute(
                        """INSERT INTO terminal_logs 
                           (username, command, output, exit_code, time, duration) 
                           VALUES (?,?,?,?,?,?)""",
                        (user, cmd, "\n".join(full_output[:10000]), exit_code, 
                         datetime.now().isoformat(), duration)
                    )
            except Exception as e:
                server_log('error', f'Command log error: {e}')
                emit('log', {'msg': f'⚠️ Failed to save command log', 'type': 'warning'})
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f'❌ Error: {str(e)} ({duration:.2f}s)'
            emit('log', {'msg': error_msg, 'type': 'error'})
            emit('command_end', {'success': False, 'duration': round(duration, 2)})
            server_log('error', f'Command execution error: {e}')
    
    # Run in background thread
    thread = threading.Thread(target=run_command, daemon=True)
    thread.start()

@socketio.on('save_code')
def handle_save_code(data):
    if 'user' not in session:
        emit('log', {'msg': '❌ Please login first', 'type': 'error'})
        return
    
    user = session['user']
    f_name = data['filename'].strip()
    code = data['code']
    
    # Validate filename
    if not is_safe_filename(f_name):
        emit('log', {'msg': '❌ Invalid filename', 'type': 'error'})
        emit('log', {'msg': 'Filename can contain letters, numbers, dots, underscores, and hyphens', 'type': 'info'})
        return
    
    # Validate extension
    if not has_allowed_extension(f_name):
        emit('log', {'msg': f'❌ File extension not allowed. Allowed: {", ".join(SETTINGS["allowed_extensions"])}', 'type': 'error'})
        return
    
    # Validate code length
    if len(code) > SETTINGS['max_code_length']:
        emit('log', {'msg': f'❌ Code too large (max {SETTINGS["max_code_length"]} chars)', 'type': 'error'})
        return
    
    user_dir = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_dir, exist_ok=True)
    
    path = os.path.join(user_dir, f_name)
    file_size = len(code.encode('utf-8'))
    
    # Check file size limit
    if file_size > SETTINGS['max_file_size']:
        emit('log', {'msg': f'❌ File too large (max {SETTINGS["max_file_size"] // 1024 // 1024}MB)', 'type': 'error'})
        return
    
    # Check file count limit
    try:
        with sqlite3.connect(USER_DB) as conn:
            file_count = conn.execute("SELECT COUNT(*) FROM files WHERE username=?", (user,)).fetchone()[0]
            if file_count >= SETTINGS['max_files_per_user']:
                emit('log', {'msg': f'❌ File limit reached (max {SETTINGS["max_files_per_user"]} files)', 'type': 'error'})
                return
    except:
        pass
    
    # Save file
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        
        # Save to database
        try:
            with sqlite3.connect(USER_DB) as conn:
                # Check if file exists
                existing = conn.execute(
                    "SELECT id FROM files WHERE username=? AND filename=?",
                    (user, f_name)
                ).fetchone()
                
                if existing:
                    # Update existing
                    conn.execute(
                        """UPDATE files SET code=?, file_size=?, last_modified=?
                           WHERE username=? AND filename=?""",
                        (code, file_size, datetime.now().isoformat(), user, f_name)
                    )
                    message = f'💾 File updated: {f_name}'
                else:
                    # Insert new
                    conn.execute(
                        """INSERT INTO files (username, filename, code, file_size)
                           VALUES (?,?,?,?)""",
                        (user, f_name, code, file_size)
                    )
                    message = f'💾 File saved: {f_name}'
        except Exception as e:
            server_log('error', f'Database save error: {e}')
            emit('log', {'msg': f'⚠️ Failed to save to database: {str(e)}', 'type': 'warning'})
            message = f'💾 File saved locally: {f_name}'
        
        emit('log', {'msg': message, 'type': 'info'})
        
        # Update file list
        try:
            with sqlite3.connect(USER_DB) as conn:
                files = conn.execute(
                    "SELECT filename, time, file_size FROM files WHERE username=? ORDER BY time DESC LIMIT 20",
                    (user,)
                ).fetchall()
            
            emit('file_list', {'files': [
                {'filename': f[0], 'time': f[1], 'file_size': f[2] or 0}
                for f in files
            ]})
        except:
            pass
        
        server_log('info', f'File saved: {user}/{f_name} ({file_size} bytes)')
        
    except Exception as e:
        error_msg = f'❌ Error saving file: {str(e)}'
        emit('log', {'msg': error_msg, 'type': 'error'})
        server_log('error', f'File save error: {e}')

@socketio.on('save_and_run')
def handle_save_and_run(data):
    # First save the code
    handle_save_code(data)
    
    if 'user' not in session:
        return
    
    user = session['user']
    f_name = data['filename'].strip()
    
    # Then run if it's a Python file
    if f_name.endswith('.py'):
        def execute_python():
            start_time = time.time()
            try:
                emit('log', {'msg': f'🚀 Running {f_name}...', 'type': 'cmd'})
                
                user_dir = os.path.join(PROJECT_DIR, user)
                file_path = os.path.join(user_dir, f_name)
                
                if not os.path.exists(file_path):
                    emit('log', {'msg': f'❌ File not found: {f_name}', 'type': 'error'})
                    return
                
                # Run Python file
                process = subprocess.Popen(
                    ['python', f_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=user_dir,
                    bufsize=1,
                    universal_newlines=True,
                    errors='replace'
                )
                
                # Set timeout
                def kill_process():
                    try:
                        process.terminate()
                        process.wait(timeout=1)
                    except:
                        try:
                            process.kill()
                        except:
                            pass
                
                timer = threading.Timer(SETTINGS['command_timeout'], kill_process)
                timer.start()
                
                # Read output
                output_lines = []
                while True:
                    if process.stdout:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            line = output.rstrip('\n')
                            emit('log', {'msg': line, 'type': 'output'})
                            output_lines.append(line)
                
                timer.cancel()
                exit_code = process.wait()
                duration = time.time() - start_time
                
                if exit_code == 0:
                    emit('log', {'msg': f'✅ Execution completed ({duration:.2f}s)', 'type': 'success'})
                else:
                    emit('log', {'msg': f'❌ Execution failed with exit code {exit_code} ({duration:.2f}s)', 'type': 'error'})
                
                # Log execution
                try:
                    with sqlite3.connect(LOG_DB) as conn:
                        conn.execute(
                            """INSERT INTO terminal_logs 
                               (username, command, output, exit_code, time, duration) 
                               VALUES (?,?,?,?,?,?)""",
                            (user, f"python {f_name}", "\n".join(output_lines[:10000]), 
                             exit_code, datetime.now().isoformat(), duration)
                        )
                except Exception as e:
                    server_log('error', f'Execution log error: {e}')
                
                server_log('info', f'Python executed: {user}/{f_name} ({duration:.2f}s)')
                
            except Exception as e:
                duration = time.time() - start_time
                error_msg = f'❌ Execution error: {str(e)} ({duration:.2f}s)'
                emit('log', {'msg': error_msg, 'type': 'error'})
                server_log('error', f'Python execution error: {e}')
        
        # Run in background thread
        threading.Thread(target=execute_python, daemon=True).start()
    else:
        emit('log', {'msg': f'📄 File saved (not a Python file, not executed)', 'type': 'info'})

@socketio.on('restore_session')
def handle_restore_session():
    if 'user' in session:
        user = session['user']
        try:
            with sqlite3.connect(USER_DB) as conn:
                last_file = conn.execute(
                    "SELECT filename, code FROM files WHERE username=? ORDER BY time DESC LIMIT 1",
                    (user,)
                ).fetchone()
                if last_file:
                    emit('session_restore', {'last_file': {
                        'filename': last_file[0],
                        'code': last_file[1]
                    }})
        except Exception as e:
            server_log('error', f'Session restore error: {e}')

# Background tasks
def background_tasks():
    """Run background maintenance tasks"""
    while True:
        try:
            time.sleep(SETTINGS['backup_interval'])
            cleanup()
        except Exception as e:
            server_log('error', f'Background task error: {e}')
        time.sleep(60)  # Check every minute

# Start background thread
bg_thread = threading.Thread(target=background_tasks, daemon=True)
bg_thread.start()

# Global start time for uptime calculation
app_start_time = time.time()

# Run the application
if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 CYBER 20 UN SERVER STARTING...")
    print("="*70)
    print(f"🔑 Main Interface: https://[YOUR_APP].onrender.com/?key={ACCESS_KEYS['server_key']}")
    print(f"🔑 Access Portal: https://[YOUR_APP].onrender.com/access/{ACCESS_KEYS['access_key']}")
    print(f"🔑 Ghost Mode: https://[YOUR_APP].onrender.com/ghost/{ACCESS_KEYS['ghost_key']}")
    print("="*70)
    print(f"📁 Project Directory: {PROJECT_DIR}")
    print(f"💾 Databases: {USER_DB}, {LOG_DB}")
    print(f"⚡ Transport: polling only (Render.com compatible)")
    print(f"🔒 Safe Mode: Enabled")
    print(f"⏰ Command Timeout: {SETTINGS['command_timeout']}s")
    print(f"📄 Max File Size: {SETTINGS['max_file_size'] // 1024 // 1024}MB")
    print("="*70 + "\n")
    
    server_log('info', 'Server starting up...')
    
    port = int(os.environ.get('PORT', 8000))
    
    try:
        socketio.run(app,
                    host='0.0.0.0',
                    port=port,
                    debug=False,
                    allow_unsafe_werkzeug=True,
                    log_output=False)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down server...")
        cleanup()
        server_log('info', 'Server shutting down')
        sys.exit(0)
    except Exception as e:
        server_log('error', f'Server error: {e}')
        traceback.print_exc()
        sys.exit(1)
