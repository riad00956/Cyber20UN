import os
import subprocess
import threading
import sqlite3
import time
import hashlib
import secrets
from datetime import datetime
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit
import eventlet
eventlet.monkey_patch()

# Flask & SocketIO Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   transports=['websocket', 'polling'],
                   async_mode='eventlet',
                   ping_timeout=60,
                   ping_interval=25)

# Database Paths
USER_DB = "cyber_vault.db"
LOG_DB = "terminal_history.db"
PROJECT_DIR = "user_projects"
SECRET_KEY_FILE = "secret_key.txt"

# Create directories
os.makedirs(PROJECT_DIR, exist_ok=True)

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
        print(f"Access Keys Generated:\n"
              f"Server URL: http://[YOUR_IP]:8000/?key={keys['server_key']}\n"
              f"Access URL: http://[YOUR_IP]:8000/access/{keys['access_key']}\n"
              f"Ghost URL: http://[YOUR_IP]:8000/ghost/{keys['ghost_key']}")
    else:
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

ACCESS_KEYS = generate_access_keys()

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Database Initialize ---
def init_dbs():
    # User & File Database
    with sqlite3.connect(USER_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                       (id INTEGER PRIMARY KEY, 
                        username TEXT UNIQUE, 
                        password TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files 
                       (id INTEGER PRIMARY KEY, 
                        username TEXT, 
                        filename TEXT, 
                        code TEXT, 
                        time TEXT,
                        FOREIGN KEY(username) REFERENCES users(username))''')
    
    # Terminal Logs Database
    with sqlite3.connect(LOG_DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS terminal_logs 
                       (id INTEGER PRIMARY KEY, 
                        username TEXT, 
                        command TEXT, 
                        output TEXT, 
                        time TEXT,
                        FOREIGN KEY(username) REFERENCES users(username))''')
        conn.execute('''CREATE INDEX IF NOT EXISTS idx_username_time 
                       ON terminal_logs(username, time DESC)''')

init_dbs()

# Safe command execution
ALLOWED_COMMANDS = {
    'ls', 'pwd', 'cd', 'cat', 'echo', 'python', 'python3',
    'pip', 'pip3', 'git', 'curl', 'wget', 'mkdir', 'rm',
    'cp', 'mv', 'find', 'grep', 'ps', 'top', 'htop'
}

def is_safe_command(command):
    # Basic security checks
    dangerous_patterns = ['rm -rf', 'dd if=', 'mkfs', ':(){:|:&};:', 'chmod 777']
    for pattern in dangerous_patterns:
        if pattern in command:
            return False
    
    # Check if it's an allowed command
    cmd_parts = command.strip().split()
    if cmd_parts:
        base_cmd = cmd_parts[0]
        if base_cmd not in ALLOWED_COMMANDS and not command.startswith('pip'):
            return False
    return True

# Safe filename validation
def is_safe_filename(filename):
    import re
    if not filename or len(filename) > 100:
        return False
    # Only allow alphanumeric, dots, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        return False
    # Prevent directory traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    return True

# --- UI Template (Unchanged) ---
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
        :root { --bg: #020617; --purple: #8b5cf6; --blue: #3b82f6; --cyan: #06b6d4; --text: #f8fafc; --glass: rgba(15, 23, 42, 0.6); --border: rgba(255, 255, 255, 0.1); }
        * { box-sizing: border-box; transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1); }
        body { margin: 0; font-family: 'Poppins', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; display: flex; flex-direction: column; }
        #bgCanvas { position: fixed; top: 0; left: 0; z-index: -1; filter: blur(2px); }
        .container { max-width: 850px; margin: auto; padding: 25px; width: 100%; position: relative; z-index: 1; }
        .cyber-logo { width: 40px; height: 40px; background: linear-gradient(135deg, var(--purple), var(--blue)); border-radius: 10px; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 15px rgba(139, 92, 246, 0.5); animation: logo-float 3s infinite; }
        @keyframes logo-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        .card { background: var(--glass); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 28px; padding: 30px; margin-bottom: 30px; box-shadow: 0 0 20px rgba(139, 92, 246, 0.1); }
        .status-box { display: flex; align-items: center; gap: 10px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 6px 15px; border-radius: 50px; color: #10b981; font-size: 13px; font-weight: 600; }
        input, textarea { background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border); color: var(--text); padding: 16px; border-radius: 18px; width: 100%; font-family: 'Fira Code', monospace; margin-bottom: 20px; outline: none; }
        .btn { background: linear-gradient(45deg, var(--purple), var(--blue)); color: white; border: none; padding: 18px; border-radius: 18px; font-weight: 700; cursor: pointer; width: 100%; display: flex; align-items: center; justify-content: center; gap: 12px; font-size: 16px; }
        #terminal { background: #000; color: #a5f3fc; height: 240px; overflow-y: auto; padding: 18px; border-radius: 18px; font-family: 'Fira Code', monospace; font-size: 13px; border: 1px solid var(--border); }
        .log-line { border-left: 2px solid var(--purple); padding-left: 10px; margin-bottom: 4px; white-space: pre-wrap; }
        .cmd-prompt { color: #10b981; }
        .error { color: #ef4444; }
        .success { color: #10b981; }
        .warning { color: #f59e0b; }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
    <div class="container">
        {% if not logged_in %}
        <div class="card" style="margin-top: 50px; text-align: center;">
            <h2>Cyber 20 Login</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="btn">Initialize</button>
            </form>
        </div>
        {% else %}
        <header style="display:flex; justify-content:space-between; align-items:center; margin-bottom:30px;">
            <div style="display:flex; align-items:center; gap:12px;">
                <div class="cyber-logo"><i data-lucide="terminal" color="white"></i></div>
                <h2 style="margin:0; background: linear-gradient(to right, var(--purple), var(--cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Cyber 20 UN</h2>
            </div>
            <div class="status-box" id="statusIndicator">ONLINE 🟢</div>
        </header>

        <div class="card">
            <input type="text" id="filename" placeholder="main.py" value="main.py">
            <textarea id="code" style="height:150px;" placeholder="# Write Code..."></textarea>
            <button onclick="runCode()" class="btn"><i data-lucide="play-circle"></i> Save & Deploy</button>
        </div>

        <div class="card">
            <div id="terminal"></div>
            <div style="display: flex; gap: 12px; margin-top: 20px;">
                <input type="text" id="cmd" placeholder="Enter command..." style="margin-bottom:0" onkeypress="handleKeyPress(event)">
                <button onclick="sendCommand()" class="btn" style="width:70px;"><i data-lucide="chevron-right"></i></button>
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: var(--cyan);">
                Allowed commands: python, pip, git, ls, cd, cat, echo, curl, wget, etc.
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        lucide.createIcons();
        const socket = io({transports: ['websocket', 'polling']});
        
        // Background Animation
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let particles = [];
        function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
        window.onresize = resize; resize();
        class Ball { constructor() { this.reset(); } reset() { this.x = Math.random() * canvas.width; this.y = -20; this.r = Math.random() * 5 + 2; this.speed = Math.random() * 2 + 1; } update() { this.y += this.speed; if(this.y > canvas.height) this.reset(); } draw() { ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI*2); ctx.fillStyle = '#8b5cf6'; ctx.globalAlpha = 0.2; ctx.fill(); } }
        for(let i=0; i<30; i++) particles.push(new Ball());
        function loop() { ctx.clearRect(0,0,canvas.width,canvas.height); particles.forEach(p=>{p.update();p.draw();}); requestAnimationFrame(loop); }
        loop();

        // Connection status
        socket.on('connect', () => {
            document.getElementById('statusIndicator').innerHTML = 'ONLINE 🟢';
            addLog('Connected to server', 'success');
        });
        
        socket.on('disconnect', () => {
            document.getElementById('statusIndicator').innerHTML = 'OFFLINE 🔴';
            addLog('Disconnected from server', 'warning');
        });

        // Terminal Live Update
        socket.on('log', (data) => {
            addLog(data.msg, data.type || 'normal');
        });

        function addLog(message, type = 'normal') {
            const t = document.getElementById('terminal');
            const div = document.createElement('div');
            div.className = 'log-line';
            
            let prefix = '';
            if (type === 'cmd') prefix = '<span class="cmd-prompt">$ </span>';
            else if (type === 'error') prefix = '<span class="error">✗ </span>';
            else if (type === 'success') prefix = '<span class="success">✓ </span>';
            
            div.innerHTML = prefix + message;
            t.appendChild(div);
            t.scrollTop = t.scrollHeight;
        }

        function runCode() {
            const f = document.getElementById('filename').value;
            const c = document.getElementById('code').value;
            if (!f || !c) {
                addLog('Filename and code are required', 'error');
                return;
            }
            socket.emit('save_and_run', {filename: f, code: c});
            addLog(`Running ${f}...`, 'cmd');
        }

        function sendCommand() {
            const c = document.getElementById('cmd').value.trim();
            if(!c) return;
            socket.emit('execute_command', {command: c});
            addLog(c, 'cmd');
            document.getElementById('cmd').value = '';
        }

        function handleKeyPress(e) {
            if (e.key === 'Enter') {
                sendCommand();
            }
        }

        // Load previous session data
        socket.on('session_restore', (data) => {
            if (data.last_file) {
                document.getElementById('filename').value = data.last_file.filename;
                document.getElementById('code').value = data.last_file.code;
                addLog(`Restored previous file: ${data.last_file.filename}`, 'success');
            }
        });

        // Request session restore
        socket.emit('restore_session');
    </script>
</body>
</html>"""

# Ghost Mode Template
GHOST_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Ghost Mode</title>
    <style>
        body { 
            background: #000; 
            color: #0f0; 
            font-family: monospace;
            margin: 0;
            padding: 20px;
        }
        .matrix {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.3;
        }
        .content {
            max-width: 800px;
            margin: 50px auto;
            border: 1px solid #0f0;
            padding: 20px;
            background: rgba(0, 255, 0, 0.05);
        }
        h1 { text-align: center; }
        .status { color: #ff0; }
        .alert { color: #f00; }
    </style>
</head>
<body>
    <div class="content">
        <h1>👻 GHOST MODE</h1>
        <p>Server Status: <span class="status">ACTIVE</span></p>
        <p>Connection: ENCRYPTED</p>
        <p>Users Online: {{ user_count }}</p>
        <p class="alert">WARNING: This is a restricted access area</p>
    </div>
</body>
</html>
"""

# Access Mode Template
ACCESS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Access Portal</title>
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Arial', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .portal {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
        }
        .info-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: left;
        }
        .key {
            font-family: monospace;
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 5px;
            word-break: break-all;
        }
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 16px;
            cursor: pointer;
            margin: 10px;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="portal">
        <h1>🔐 Access Portal</h1>
        <div class="info-box">
            <h3>Server Information</h3>
            <p><strong>Status:</strong> 🟢 Online</p>
            <p><strong>URL:</strong> <span class="key">{{ server_url }}</span></p>
            <p><strong>Access Key:</strong> <span class="key">{{ access_key }}</span></p>
            <p><strong>Ghost Key:</strong> <span class="key">{{ ghost_key }}</span></p>
        </div>
        <p>Use the keys above to access different modes</p>
        <a href="/" class="btn">Main Interface</a>
        <a href="/status" class="btn">Server Status</a>
    </div>
</body>
</html>
"""

# --- Server Routes & Logic ---

@app.route('/')
def index():
    # Check for key-based access
    key = request.args.get('key')
    if key == ACCESS_KEYS['server_key']:
        session['user'] = 'admin'
        session.permanent = True
        return render_template_string(HTML_TEMPLATE, logged_in=True, username='admin')
    
    if 'user' not in session:
        return render_template_string(HTML_TEMPLATE, logged_in=False)
    
    return render_template_string(HTML_TEMPLATE, logged_in=True, username=session.get('user'))

@app.route('/access/<key>')
def access_mode(key):
    if key == ACCESS_KEYS['access_key']:
        return render_template_string(ACCESS_TEMPLATE, 
                                    server_url=request.host_url,
                                    access_key=ACCESS_KEYS['access_key'],
                                    ghost_key=ACCESS_KEYS['ghost_key'])
    return "Invalid Access Key", 403

@app.route('/ghost/<key>')
def ghost_mode(key):
    if key == ACCESS_KEYS['ghost_key']:
        # Get active user count
        active_users = len(session.get('active_users', []))
        return render_template_string(GHOST_TEMPLATE, user_count=active_users)
    return "Invalid Ghost Key", 403

@app.route('/status')
def status():
    # Get server statistics
    with sqlite3.connect(USER_DB) as conn:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        file_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    
    with sqlite3.connect(LOG_DB) as conn:
        cmd_count = conn.execute("SELECT COUNT(*) FROM terminal_logs").fetchone()[0]
    
    return jsonify({
        'status': 'online',
        'users': user_count,
        'files': file_count,
        'commands': cmd_count,
        'uptime': time.time() - app_start_time,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username', '').strip()
    p = request.form.get('password', '').strip()
    
    if not u or not p:
        return redirect(url_for('index'))
    
    hashed_pwd = hash_password(p)
    
    with sqlite3.connect(USER_DB) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, password) VALUES (?,?)", (u, hashed_pwd))
        else:
            # Verify password
            if user[2] != hashed_pwd:
                return "Invalid credentials", 401
        
        session['user'] = u
        session.permanent = True
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        emit('log', {'msg': f"Welcome back, {session['user']}!", 'type': 'success'})
        # Send session restore data
        with sqlite3.connect(USER_DB) as conn:
            last_file = conn.execute(
                "SELECT filename, code FROM files WHERE username=? ORDER BY time DESC LIMIT 1",
                (session['user'],)
            ).fetchone()
            if last_file:
                emit('session_restore', {'last_file': {
                    'filename': last_file[0],
                    'code': last_file[1]
                }})

@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session:
        emit('log', {'msg': 'Please login first', 'type': 'error'})
        return
    
    user = session['user']
    cmd = data['command'].strip()
    
    if not cmd:
        emit('log', {'msg': 'Empty command', 'type': 'warning'})
        return
    
    # Security check
    if not is_safe_command(cmd):
        emit('log', {'msg': 'Command not allowed for security reasons', 'type': 'error'})
        return
    
    emit('log', {'msg': f'Executing: {cmd}', 'type': 'cmd'})
    
    def run_command():
        try:
            # Change to user's project directory
            user_dir = os.path.join(PROJECT_DIR, user)
            os.makedirs(user_dir, exist_ok=True)
            
            # Use shell with timeout
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=user_dir,
                env=env,
                universal_newlines=True
            )
            
            full_output = []
            start_time = time.time()
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    emit('log', {'msg': line, 'type': 'normal'})
                    full_output.append(line)
                
                # Timeout after 30 seconds
                if time.time() - start_time > 30:
                    process.terminate()
                    emit('log', {'msg': 'Command timeout (30s)', 'type': 'error'})
                    break
            
            return_code = process.wait()
            
            if return_code == 0:
                emit('log', {'msg': 'Command completed successfully', 'type': 'success'})
            else:
                emit('log', {'msg': f'Command failed with exit code {return_code}', 'type': 'error'})
            
            # Save to database
            with sqlite3.connect(LOG_DB) as conn:
                conn.execute(
                    "INSERT INTO terminal_logs (username, command, output, time) VALUES (?,?,?,?)",
                    (user, cmd, "\n".join(full_output), datetime.now().isoformat())
                )
            
        except Exception as e:
            emit('log', {'msg': f'Error: {str(e)}', 'type': 'error'})
    
    # Run in thread pool
    socketio.start_background_task(run_command)

@socketio.on('save_and_run')
def handle_run(data):
    if 'user' not in session:
        emit('log', {'msg': 'Please login first', 'type': 'error'})
        return
    
    user = session['user']
    f_name = data['filename'].strip()
    code = data['code']
    
    # Validate filename
    if not is_safe_filename(f_name):
        emit('log', {'msg': 'Invalid filename', 'type': 'error'})
        return
    
    # Create user directory
    user_dir = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_dir, exist_ok=True)
    
    path = os.path.join(user_dir, f_name)
    
    # Save file
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        
        # Save to database
        with sqlite3.connect(USER_DB) as conn:
            conn.execute(
                "INSERT INTO files (username, filename, code, time) VALUES (?,?,?,?)",
                (user, f_name, code, datetime.now().isoformat())
            )
        
        emit('log', {'msg': f'File saved: {f_name}', 'type': 'success'})
        
        # Run Python file
        if f_name.endswith('.py'):
            def execute_python():
                try:
                    emit('log', {'msg': f'Running {f_name}...', 'type': 'cmd'})
                    
                    process = subprocess.Popen(
                        ['python', f_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        cwd=user_dir,
                        bufsize=1,
                        universal_newlines=True
                    )
                    
                    for line in iter(process.stdout.readline, ''):
                        emit('log', {'msg': line.strip(), 'type': 'normal'})
                    
                    process.wait()
                    emit('log', {'msg': 'Execution completed', 'type': 'success'})
                    
                except Exception as e:
                    emit('log', {'msg': f'Execution error: {str(e)}', 'type': 'error'})
            
            socketio.start_background_task(execute_python)
    
    except Exception as e:
        emit('log', {'msg': f'Error saving file: {str(e)}', 'type': 'error'})

@app.route('/api/files/<username>')
def get_user_files(username):
    if 'user' not in session or session['user'] != username:
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect(USER_DB) as conn:
        files = conn.execute(
            "SELECT filename, code, time FROM files WHERE username=? ORDER BY time DESC",
            (username,)
        ).fetchall()
    
    return jsonify([
        {'filename': f[0], 'code': f[1], 'time': f[2]}
        for f in files
    ])

# Global start time for uptime calculation
app_start_time = time.time()

if __name__ == '__main__':
    print("\n" + "="*50)
    print("Cyber 20 UN Server Starting...")
    print(f"Server URL: http://0.0.0.0:8000/?key={ACCESS_KEYS['server_key']}")
    print(f"Access URL: http://0.0.0.0:8000/access/{ACCESS_KEYS['access_key']}")
    print(f"Ghost URL: http://0.0.0.0:8000/ghost/{ACCESS_KEYS['ghost_key']}")
    print("="*50 + "\n")
    
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=port, 
                 debug=False,
                 allow_unsafe_werkzeug=True)
