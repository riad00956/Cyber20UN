import os
import subprocess
import threading
import sqlite3
import hashlib
import secrets
import sys
from flask import Flask, render_template_string, request, session, redirect
from flask_socketio import SocketIO, emit

# --- Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
# Render compatibility for SocketIO
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

# --- Helper: Command Executor ---
def execute_system_command(cmd, user_path, user):
    """কমান্ড রান করার মূল ফাংশন যা টার্মিনালে আউটপুট পাঠাবে"""
    socketio.emit('log', {'msg': f'user@{user}:~$ {cmd}', 'type': 'cmd'})
    
    def run():
        # subprocess.STDOUT stderr-কেও stdout-এ নিয়ে আসে
        process = subprocess.Popen(
            cmd, shell=True, cwd=user_path,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
            text=True, bufsize=1, universal_newlines=True
        )
        
        for line in iter(process.stdout.readline, ''):
            if line:
                socketio.emit('log', {'msg': line.rstrip(), 'type': 'output'})
        
        process.stdout.close()
        process.wait()
        socketio.emit('log', {'msg': '--- Execution Finished ---', 'type': 'info'})

    threading.Thread(target=run).start()

# --- Routes ---
@app.route('/')
def index():
    if 'user' not in session: return render_template_string(HTML_UI, logged_in=False)
    return render_template_string(HTML_UI, logged_in=True, username=session['user'])

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username').lower().strip(), request.form.get('password')
    hp = hashlib.sha256(p.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user: conn.execute("INSERT INTO users VALUES (?,?)", (u, hp))
        elif user['password'] != hp: return "Login Failed", 401
    session['user'] = u
    return redirect('/')

# --- Socket Events ---
@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command'].strip()
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    execute_system_command(cmd, user_path, user)

@socketio.on('save_run')
def save_run(data):
    if 'user' not in session: return
    user = session['user']
    filename = data['filename'].strip()
    code = data['code']
    
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    # ফাইলটি ডিস্কে সেভ করা
    path = os.path.join(user_path, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)
    
    # রান কমান্ড তৈরি (python বা python3 চেক)
    run_cmd = f"python3 {filename}"
    execute_system_command(run_cmd, user_path, user)

# --- Mobile UI ---
HTML_UI = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cyber 20 UN IDE</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { margin: 0; background: #08080c; color: #e0e0e0; font-family: 'Courier New', monospace; overflow: hidden; }
        .container { display: flex; flex-direction: column; height: 100vh; }
        .header { background: #1a1a2e; padding: 12px; border-bottom: 2px solid #bc13fe; font-size: 13px; font-weight: bold; display: flex; justify-content: space-between; }
        
        .content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .section { flex: 1; display: flex; flex-direction: column; padding: 8px; box-sizing: border-box; min-height: 0; }
        
        h3 { margin: 0 0 5px 0; font-size: 12px; color: #00f2ff; letter-spacing: 1px; }
        
        textarea, #terminal { 
            flex: 1; background: #000; color: #0f0; border: 1px solid #333; 
            padding: 10px; font-family: 'Fira Code', monospace; font-size: 13px; 
            border-radius: 4px; outline: none; resize: none;
        }
        #terminal { overflow-y: auto; white-space: pre-wrap; color: #a5f3fc; border-color: #bc13fe; }
        
        input { 
            background: #111; color: #fff; border: 1px solid #333; 
            padding: 10px; border-radius: 4px; margin-bottom: 5px; font-size: 14px;
        }
        .btn { 
            background: linear-gradient(45deg, #bc13fe, #7a12f5); color: #fff; border: none; 
            padding: 12px; border-radius: 4px; font-weight: bold; cursor: pointer; text-transform: uppercase;
        }
        
        .cmd-line { color: #00f2ff; font-weight: bold; margin-top: 5px; }
        .info-line { color: #bc13fe; font-style: italic; }
        
        @media (min-width: 768px) {
            .content { flex-direction: row; }
        }
    </style>
</head>
<body>
    {% if not logged_in %}
    <div style="padding: 50px 20px; text-align: center;">
        <h2 style="color:#bc13fe;">CYBER 20 UN</h2>
        <form action="/login" method="POST" style="display:flex; flex-direction:column; gap:15px; max-width:300px; margin:auto;">
            <input type="text" name="username" placeholder="Enter Username" required>
            <input type="password" name="password" placeholder="Enter Password" required>
            <button class="btn">Start Session</button>
        </form>
    </div>
    {% else %}
    <div class="container">
        <div class="header">
            <span>ID: {{ username }}</span>
            <span style="color:#00f2ff;">CYBER 20 UN</span>
        </div>
        <div class="content">
            <div class="section">
                <h3>[#] EDITOR</h3>
                <input type="text" id="fname" value="main.py" spellcheck="false" autocomplete="off">
                <textarea id="code" spellcheck="false" autocomplete="off">print("System Check Success!")
import sys
print(f"Python Version: {sys.version}")</textarea>
                <button class="btn" style="margin-top:5px;" onclick="runCode()">Save & Execute</button>
            </div>
            <div class="section">
                <h3>[>] TERMINAL</h3>
                <div id="terminal"></div>
                <input type="text" id="cmd" placeholder="Enter Command..." 
                       style="margin-top:5px; border-color: #bc13fe;" 
                       onkeypress="if(event.key==='Enter') sendCmd()"
                       autocapitalize="none" autocomplete="off" spellcheck="false">
                <button class="btn" style="background:#333; margin-top:5px; font-size:10px; padding:5px;" onclick="document.getElementById('terminal').innerHTML=''">Clear Terminal</button>
            </div>
        </div>
    </div>
    <script>
        const socket = io({transports: ['polling']});
        const term = document.getElementById('terminal');

        socket.on('log', (data) => {
            const div = document.createElement('div');
            if(data.type === 'cmd') div.className = 'cmd-line';
            if(data.type === 'info') div.className = 'info-line';
            div.textContent = data.msg;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        });

        function runCode() {
            const filename = document.getElementById('fname').value;
            const code = document.getElementById('code').value;
            if(!filename.endsWith('.py')) {
                alert("Please use .py extension");
                return;
            }
            socket.emit('save_run', {filename, code});
        }

        function sendCmd() {
            const cmdInput = document.getElementById('cmd');
            const cmd = cmdInput.value.trim();
            if(!cmd) return;
            socket.emit('execute_command', {command: cmd});
            cmdInput.value = '';
        }
    </script>
    {% endif %}
</body>
</html>
"""

if __name__ == '__main__':
    # Render default port is 10000
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
