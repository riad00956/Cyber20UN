import os
import subprocess
import threading
import sqlite3
import time
import hashlib
import secrets
import json
import re
import shutil
import sys
import traceback
import atexit
from datetime import datetime
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 # 24 Hours

# Render.com compatibility
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='threading', 
                   transports=['polling', 'websocket'])

USER_DB = "cyber_vault.db"
LOG_DB = "terminal_history.db"
PROJECT_DIR = os.path.abspath("user_projects")
SETTINGS_FILE = "server_settings.json"
SECRET_KEY_FILE = "secret_key.txt"

os.makedirs(PROJECT_DIR, exist_ok=True)

# --- Database Helper ---
def get_db_connection(db_name):
    conn = sqlite3.connect(db_name, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# --- Initialize Databases ---
def init_dbs():
    with get_db_connection(USER_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        code TEXT,
                        file_size INTEGER,
                        last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    with get_db_connection(LOG_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS terminal_logs 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        command TEXT NOT NULL,
                        output TEXT,
                        exit_code INTEGER,
                        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
init_dbs()

# --- Security Helpers ---
def hash_password(password):
    salt = secrets.token_hex(8)
    return salt + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password, stored_password):
    salt = stored_password[:16]
    return stored_password == salt + hashlib.sha256((salt + password).encode()).hexdigest()

def is_safe_path(path, user):
    user_home = os.path.join(PROJECT_DIR, user)
    return os.path.abspath(path).startswith(user_home)

def is_safe_command(command):
    dangerous = [r'rm\s+-rf\s+/', r'mkfs', r'dd\s+', r'sudo', r'su\s+', r'>\s*/dev/']
    for pattern in dangerous:
        if re.search(pattern, command): return False
    return True

# --- Access Keys Management ---
def get_access_keys():
    if not os.path.exists(SECRET_KEY_FILE):
        keys = {'server': secrets.token_hex(12), 'access': secrets.token_hex(12), 'ghost': secrets.token_hex(12)}
        with open(SECRET_KEY_FILE, 'w') as f: json.dump(keys, f)
    else:
        with open(SECRET_KEY_FILE, 'r') as f: keys = json.load(f)
    return keys

KEYS = get_access_keys()

# --- UI Template (Optimized) ---
# (এখানে আপনার দেওয়া HTML_TEMPLATE টি ব্যবহার করা হয়েছে, শুধু লজিক্যাল সংযোগগুলো ঠিক করা হয়েছে)
# সংক্ষেপ করার জন্য এখানে HTML এর অংশটি আগের মতোই থাকবে।

@app.route('/')
def index():
    key = request.args.get('key')
    if key == KEYS['server']:
        session['user'] = 'admin'
        session['cwd'] = os.path.join(PROJECT_DIR, 'admin')
    
    if 'user' not in session:
        return render_template_string(HTML_TEMPLATE, logged_in=False)
    
    return render_template_string(HTML_TEMPLATE, logged_in=True, username=session['user'], session_id=secrets.token_hex(4), settings={'command_timeout': 30})

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username'), request.form.get('password')
    if not u or not p: return redirect('/')
    
    with get_db_connection(USER_DB) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, hash_password(p)))
            user_dir = os.path.join(PROJECT_DIR, u)
            os.makedirs(user_dir, exist_ok=True)
        else:
            if not verify_password(p, user['password']): return "Wrong credentials", 401
            
    session['user'] = u
    session['cwd'] = os.path.join(PROJECT_DIR, u)
    os.makedirs(session['cwd'], exist_ok=True)
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- SocketIO Terminal Logic ---
@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command'].strip()
    
    if not is_safe_command(cmd):
        emit('log', {'msg': '❌ Security Block: Unsafe Command', 'type': 'error'})
        return

    # Virtual CWD handling
    if 'cwd' not in session: session['cwd'] = os.path.join(PROJECT_DIR, user)
    
    if cmd.startswith('cd '):
        new_path = os.path.abspath(os.path.join(session['cwd'], cmd[3:].strip()))
        if is_safe_path(new_path, user) and os.path.isdir(new_path):
            session['cwd'] = new_path
            emit('log', {'msg': f'Directory changed to: {os.path.basename(new_path) or "/"}', 'type': 'info'})
        else:
            emit('log', {'msg': '❌ Invalid or Restricted Directory', 'type': 'error'})
        return

    def run_proc():
        try:
            # Subprocess execution in user's virtual CWD
            proc = subprocess.Popen(
                cmd, shell=True, cwd=session['cwd'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            
            for line in iter(proc.stdout.readline, ''):
                emit('log', {'msg': line.strip(), 'type': 'output'})
            
            proc.wait()
            # Log to DB
            with get_db_connection(LOG_DB) as conn:
                conn.execute("INSERT INTO terminal_logs (username, command, exit_code) VALUES (?, ?, ?)",
                            (user, cmd, proc.returncode))
        except Exception as e:
            emit('log', {'msg': str(e), 'type': 'error'})

    threading.Thread(target=run_proc).start()

@socketio.on('save_code')
def save_file(data):
    if 'user' not in session: return
    user, filename, code = session['user'], data['filename'], data['code']
    
    file_path = os.path.join(PROJECT_DIR, user, filename)
    if not is_safe_path(file_path, user):
        emit('log', {'msg': '❌ Restricted Filename', 'type': 'error'})
        return

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        with get_db_connection(USER_DB) as conn:
            conn.execute("INSERT OR REPLACE INTO files (username, filename, code, file_size) VALUES (?, ?, ?, ?)",
                        (user, filename, code, len(code)))
        emit('log', {'msg': f'✅ Saved {filename}', 'type': 'success'})
        handle_get_files() # Refresh file list
    except Exception as e:
        emit('log', {'msg': f'Error: {str(e)}', 'type': 'error'})

@socketio.on('get_files')
def handle_get_files():
    if 'user' not in session: return
    with get_db_connection(USER_DB) as conn:
        files = conn.execute("SELECT filename, last_modified, file_size FROM files WHERE username=? ORDER BY last_modified DESC", 
                            (session['user'],)).fetchall()
    
    file_list = [dict(f) for f in files]
    emit('file_list', {'files': file_list})

@socketio.on('get_server_stats')
def get_stats():
    uptime = int(time.time() - start_time)
    emit('server_stats', {
        'uptime': f"{uptime//60}m {uptime%60}s",
        'user_count': 1, # Simplified
        'command_count': 0
    })

# --- API for File Download/Load ---
@app.route('/api/file/<filename>')
def load_file(filename):
    if 'user' not in session: return jsonify({'success': False}), 401
    file_path = os.path.join(PROJECT_DIR, session['user'], filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return jsonify({'success': True, 'filename': filename, 'code': f.read()})
    return jsonify({'success': False}), 404

# --- Start Server ---
start_time = time.time()
if __name__ == '__main__':
    print(f"Server Keys: {KEYS}")
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
