import os
import subprocess
import threading
import sqlite3
import time
import hashlib
import secrets
import json
import sys
from datetime import datetime
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit

# --- Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', transports=['polling'])

USER_DB = "cyber_vault.db"
PROJECT_DIR = os.path.abspath("user_projects")
os.makedirs(PROJECT_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(USER_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# Database Init
with get_db() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS files (username TEXT, filename TEXT, code TEXT, PRIMARY KEY(username, filename))')

# --- Logic ---
@app.route('/')
def index():
    if 'user' not in session: return render_template_string(HTML_UI, logged_in=False)
    return render_template_string(HTML_UI, logged_in=True, username=session['user'])

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username'), request.form.get('password')
    hp = hashlib.sha256(p.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user: conn.execute("INSERT INTO users VALUES (?,?)", (u, hp))
        elif user['password'] != hp: return "Error", 401
    session['user'] = u
    return redirect('/')

# --- Terminal Fix (Immediate Output) ---
@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command'].strip()
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)

    emit('log', {'msg': f'user@{user}:~$ {cmd}', 'type': 'cmd'})

    def run():
        # Using stdbuf to disable buffering for real-time output
        process = subprocess.Popen(
            cmd, shell=True, cwd=user_path,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
            text=True, bufsize=1, universal_newlines=True
        )
        
        for line in iter(process.stdout.readline, ''):
            if line:
                socketio.emit('log', {'msg': line.strip(), 'type': 'output'})
        
        process.stdout.close()
        return_code = process.wait()
        if return_code == 0:
            socketio.emit('log', {'msg': '--- Command Finished ---', 'type': 'success'})
        else:
            socketio.emit('log', {'msg': f'--- Failed with code {return_code} ---', 'type': 'error'})

    threading.Thread(target=run).start()

@socketio.on('save_run')
def save_run(data):
    if 'user' not in session: return
    user, filename, code = session['user'], data['filename'], data['code']
    path = os.path.join(PROJECT_DIR, user, filename)
    with open(path, 'w') as f: f.write(code)
    handle_command({'command': f'python3 {filename}'})

# --- Mobile UI ---
HTML_UI = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber 20 UN Mobile</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { margin: 0; background: #050505; color: #fff; font-family: sans-serif; }
        .container { display: flex; flex-direction: column; height: 100vh; }
        .header { background: #111; padding: 10px; border-bottom: 2px solid #bc13fe; font-size: 14px; }
        
        /* Layout for Mobile */
        .content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .section { flex: 1; display: flex; flex-direction: column; padding: 5px; box-sizing: border-box; }
        
        h3 { margin: 5px 0; font-size: 14px; color: #bc13fe; text-transform: uppercase; }
        textarea, #terminal { 
            flex: 1; background: #000; color: #0f0; border: 1px solid #333; 
            padding: 10px; font-family: monospace; font-size: 12px; 
            border-radius: 5px; outline: none;
        }
        #terminal { overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
        
        input { 
            background: #111; color: #fff; border: 1px solid #bc13fe; 
            padding: 12px; border-radius: 5px; margin-bottom: 5px; 
        }
        .btn { 
            background: #bc13fe; color: #fff; border: none; 
            padding: 12px; border-radius: 5px; font-weight: bold; cursor: pointer;
        }
        
        .login-box { padding: 40px; text-align: center; }
        .cmd-line { color: #00f2ff; }
        .err-line { color: #ff4444; }

        /* Desktop Adjustments */
        @media (min-width: 768px) {
            .content { flex-direction: row; }
            .section { flex: 1; }
        }
    </style>
</head>
<body>
    {% if not logged_in %}
    <div class="login-box">
        <h2>CYBER 20 UN</h2>
        <form action="/login" method="POST" style="display:flex; flex-direction:column; gap:10px;">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button class="btn">Login / Register</button>
        </form>
    </div>
    {% else %}
    <div class="container">
        <div class="header">User: {{ username }} | Cyber 20 UN</div>
        <div class="content">
            <div class="section">
                <h3>Editor</h3>
                <input type="text" id="fname" value="main.py">
                <textarea id="code">print("Hello from Mobile!")</textarea>
                <button class="btn" style="margin-top:5px;" onclick="runCode()">Save & Run</button>
            </div>
            <div class="section">
                <h3>Terminal</h3>
                <div id="terminal"></div>
                <input type="text" id="cmd" placeholder="Command (e.g. pip install requests)" 
                       style="margin-top:5px;" onkeypress="if(event.key==='Enter') sendCmd()">
            </div>
        </div>
    </div>
    <script>
        const socket = io({transports: ['polling']});
        const term = document.getElementById('terminal');

        socket.on('log', (data) => {
            const div = document.createElement('div');
            if(data.type === 'cmd') div.className = 'cmd-line';
            if(data.type === 'error') div.className = 'err-line';
            div.textContent = data.msg;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        });

        function runCode() {
            const filename = document.getElementById('fname').value;
            const code = document.getElementById('code').value;
            socket.emit('save_run', {filename, code});
        }

        function sendCmd() {
            const cmd = document.getElementById('cmd').value;
            if(!cmd) return;
            socket.emit('execute_command', {command: cmd});
            document.getElementById('cmd').value = '';
        }
    </script>
    {% endif %}
</body>
</html>
"""

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000, allow_unsafe_werkzeug=True)
