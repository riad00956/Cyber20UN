import os
import subprocess
import threading
import sqlite3
import time
import hashlib
import secrets
import json
import re
import sys
import atexit
from datetime import datetime
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# --- INITIAL SETUP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 Hours

# SocketIO optimized for Render.com
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='threading', 
                   transports=['polling', 'websocket'],
                   ping_timeout=60)

# Constants
USER_DB = "cyber_vault.db"
LOG_DB = "terminal_history.db"
PROJECT_DIR = os.path.abspath("user_projects")
SECRET_KEY_FILE = "secret_key.txt"

os.makedirs(PROJECT_DIR, exist_ok=True)

# --- DATABASE LOGIC ---
def get_db(db_name):
    conn = sqlite3.connect(db_name, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_dbs():
    with get_db(USER_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, is_active BOOLEAN DEFAULT 1)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, filename TEXT, code TEXT, file_size INTEGER, last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    with get_db(LOG_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS terminal_logs 
                       (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, command TEXT, output TEXT, exit_code INTEGER, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
init_dbs()

# --- ACCESS KEYS ---
def load_keys():
    if not os.path.exists(SECRET_KEY_FILE):
        keys = {'server': secrets.token_hex(16), 'access': secrets.token_hex(16), 'ghost': secrets.token_hex(16)}
        with open(SECRET_KEY_FILE, 'w') as f: json.dump(keys, f)
        return keys
    return json.load(open(SECRET_KEY_FILE))

KEYS = load_keys()

# --- SECURITY UTILS ---
def hash_pwd(p): return hashlib.sha256(p.encode()).hexdigest()

def is_safe_command(cmd):
    forbidden = ['rm -rf /', 'mkfs', 'dd ', 'sudo ', 'su ', 'shutdown', 'reboot']
    return not any(f in cmd.lower() for f in forbidden)

def get_user_path(user):
    path = os.path.join(PROJECT_DIR, user)
    os.makedirs(path, exist_ok=True)
    return path

# --- ROUTES ---
@app.route('/')
def index():
    key = request.args.get('key')
    if key == KEYS['server']:
        session['user'] = 'admin'
    if 'user' not in session:
        return render_template_string(HTML_UI, logged_in=False)
    return render_template_string(HTML_UI, logged_in=True, username=session['user'], keys=KEYS)

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username'), request.form.get('password')
    if not u or not p: return redirect('/')
    hp = hash_pwd(p)
    with get_db(USER_DB) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, hp))
        elif user['password'] != hp:
            return "Invalid Credentials", 401
    session['user'] = u
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- SOCKET EVENTS (TERMINAL & CODE) ---
@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command'].strip()
    
    if not is_safe_command(cmd):
        emit('log', {'msg': '❌ Command Blocked by Security', 'type': 'error'})
        return

    emit('log', {'msg': f'user@{user}:~$ {cmd}', 'type': 'cmd'})

    def run():
        try:
            # We use the system environment but can point to local user packages if needed
            process = subprocess.Popen(
                cmd, shell=True, cwd=get_user_path(user),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                env={**os.environ, "PYTHONPATH": get_user_path(user)}
            )
            
            full_output = []
            for line in iter(process.stdout.readline, ''):
                emit('log', {'msg': line.strip(), 'type': 'output'})
                full_output.append(line)
            
            process.wait()
            with get_db(LOG_DB) as conn:
                conn.execute("INSERT INTO terminal_logs (username, command, output, exit_code) VALUES (?, ?, ?, ?)",
                            (user, cmd, "".join(full_output), process.returncode))
        except Exception as e:
            emit('log', {'msg': f'Error: {str(e)}', 'type': 'error'})

    threading.Thread(target=run).start()

@socketio.on('save_and_run')
def save_run(data):
    if 'user' not in session: return
    user, filename, code = session['user'], data['filename'], data['code']
    
    # Save to Disk
    path = os.path.join(get_user_path(user), filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)
    
    # Save to DB
    with get_db(USER_DB) as conn:
        conn.execute("INSERT OR REPLACE INTO files (username, filename, code, file_size) VALUES (?, ?, ?, ?)",
                    (user, filename, code, len(code)))
    
    emit('log', {'msg': f'✅ File {filename} saved. Executing...', 'type': 'info'})
    
    # If Python file, Run it
    if filename.endswith('.py'):
        handle_command({'command': f'python3 {filename}'})

@socketio.on('get_files')
def list_files():
    if 'user' not in session: return
    with get_db(USER_DB) as conn:
        files = conn.execute("SELECT filename, file_size, last_modified FROM files WHERE username=?", (session['user'],)).fetchall()
    emit('file_list', {'files': [dict(f) for f in files]})

# --- UI TEMPLATE (Integrated) ---
HTML_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber 20 UN - Final</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root { --bg: #0a0a12; --glass: rgba(20, 20, 35, 0.8); --cyan: #00f2ff; --purple: #bc13fe; }
        body { background: var(--bg); color: white; font-family: 'Segoe UI', sans-serif; margin: 0; display: flex; flex-direction: column; height: 100vh; }
        .header { background: var(--glass); padding: 15px; border-bottom: 1px solid var(--purple); display: flex; justify-content: space-between; }
        .main { display: flex; flex: 1; overflow: hidden; }
        .editor-pane, .terminal-pane { flex: 1; padding: 15px; display: flex; flex-direction: column; border: 1px solid #222; }
        textarea, #terminal { background: #000; color: #0f0; font-family: monospace; border: 1px solid #333; padding: 10px; flex: 1; overflow-y: auto; }
        input { background: #111; border: 1px solid var(--purple); color: white; padding: 10px; width: 100%; box-sizing: border-box; }
        .btn { background: var(--purple); color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 5px; margin: 5px 0; }
        .file-item { padding: 5px; border-bottom: 1px solid #222; font-size: 13px; }
        .login-card { background: var(--glass); padding: 40px; border-radius: 15px; border: 1px solid var(--cyan); margin: auto; width: 300px; text-align: center; }
    </style>
</head>
<body>
    {% if not logged_in %}
    <div class="login-card">
        <h2>CYBER 20 UN</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required><br><br>
            <input type="password" name="password" placeholder="Password" required><br><br>
            <button type="submit" class="btn">Initialize Session</button>
        </form>
    </div>
    {% else %}
    <div class="header">
        <div><strong>Cyber 20 UN</strong> | User: {{ username }}</div>
        <button onclick="location.href='/logout'" style="background:none; border:none; color:red; cursor:pointer;">Logout</button>
    </div>
    <div class="main">
        <div class="editor-pane">
            <h3>Code Editor</h3>
            <input type="text" id="filename" value="main.py">
            <textarea id="code">print("Hello from Cyber 20!")</textarea>
            <button class="btn" onclick="saveAndRun()">Save & Run</button>
            <div id="fileList"></div>
        </div>
        <div class="terminal-pane">
            <h3>Terminal</h3>
            <div id="terminal"></div>
            <input type="text" id="cmdInput" placeholder="Enter command (e.g. pip install requests)" onkeypress="checkEnter(event)">
        </div>
    </div>
    <script>
        const socket = io({transports: ['polling']});
        
        socket.on('log', (data) => {
            const term = document.getElementById('terminal');
            const line = document.createElement('div');
            line.style.color = data.type === 'error' ? 'red' : (data.type === 'cmd' ? '#00f2ff' : '#0f0');
            line.textContent = data.msg;
            term.appendChild(line);
            term.scrollTop = term.scrollHeight;
        });

        socket.on('file_list', (data) => {
            const list = document.getElementById('fileList');
            list.innerHTML = '<h4>Files:</h4>';
            data.files.forEach(f => {
                list.innerHTML += `<div class="file-item">${f.filename} (${f.file_size} bytes)</div>`;
            });
        });

        function saveAndRun() {
            const filename = document.getElementById('filename').value;
            const code = document.getElementById('code').value;
            socket.emit('save_and_run', {filename, code});
        }

        function checkEnter(e) {
            if(e.key === 'Enter') {
                const cmd = document.getElementById('cmdInput').value;
                socket.emit('execute_command', {command: cmd});
                document.getElementById('cmdInput').value = '';
            }
        }

        setInterval(() => socket.emit('get_files'), 5000);
    </script>
    {% endif %}
</body>
</html>
"""

# --- START SERVER ---
if __name__ == '__main__':
    start_time = time.time()
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 SERVER LIVE ON PORT {port}")
    print(f"🔑 Keys: {KEYS}")
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
