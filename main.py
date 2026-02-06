import os
import subprocess
import threading
import sqlite3
import time
from flask import Flask, render_template_string, request, session, redirect, url_for
from flask_socketio import SocketIO, emit

# Flask & SocketIO Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber_ultra_2026_pro'
# Pure WebSocket with eventlet/gevent support
socketio = SocketIO(app, cors_allowed_origins="*", transports=['websocket'], async_mode='threading')

# Database Paths
USER_DB = "cyber_vault.db"
LOG_DB = "terminal_history.db"
PROJECT_DIR = "user_projects"

if not os.path.exists(PROJECT_DIR):
    os.makedirs(PROJECT_DIR)

# --- Database Initialize ---
def init_dbs():
    # User & File Database
    with sqlite3.connect(USER_DB) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, username TEXT, filename TEXT, code TEXT, time TEXT)')
    
    # Terminal Logs Database
    with sqlite3.connect(LOG_DB) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS terminal_logs (id INTEGER PRIMARY KEY, username TEXT, command TEXT, output TEXT, time TEXT)')

init_dbs()

# --- UI (আপনার অরিজিনাল ডিজাইন হুবহু রাখা হয়েছে) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
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
        .log-line { border-left: 2px solid var(--purple); padding-left: 10px; margin-bottom: 4px; }
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
            <div class="status-box">ONLINE 🟢</div>
        </header>

        <div class="card">
            <input type="text" id="filename" placeholder="main.py" value="main.py">
            <textarea id="code" style="height:150px;" placeholder="# Write Code..."></textarea>
            <button onclick="runCode()" class="btn"><i data-lucide="play-circle"></i> Save & Deploy</button>
        </div>

        <div class="card">
            <div id="terminal"></div>
            <div style="display: flex; gap: 12px; margin-top: 20px;">
                <input type="text" id="cmd" placeholder="pip install requests..." style="margin-bottom:0">
                <button onclick="sendCommand()" class="btn" style="width:70px;"><i data-lucide="chevron-right"></i></button>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        lucide.createIcons();
        const socket = io({transports: ['websocket']});
        
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

        // Terminal Live Update
        socket.on('log', (data) => {
            const t = document.getElementById('terminal');
            const div = document.createElement('div');
            div.className = 'log-line';
            div.textContent = data.msg;
            t.appendChild(div);
            t.scrollTop = t.scrollHeight;
        });

        function runCode() {
            const f = document.getElementById('filename').value;
            const c = document.getElementById('code').value;
            socket.emit('save_and_run', {filename: f, code: c});
        }

        function sendCommand() {
            const c = document.getElementById('cmd').value;
            if(!c) return;
            socket.emit('execute_command', {command: c});
            document.getElementById('cmd').value = '';
        }
    </script>
</body>
</html>
"""

# --- Server Routes & Logic ---

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE, logged_in='user' in session, username=session.get('user'))

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username'), request.form.get('password')
    with sqlite3.connect(USER_DB) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, password) VALUES (?,?)", (u, p))
        session['user'] = u
    return redirect(url_for('index'))

@socketio.on('execute_command')
def handle_command(data):
    user, cmd = session.get('user'), data['command']
    def run():
        # রিয়েল টাইম লগের জন্য stdout.readline ব্যবহার করা হয়েছে
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        full_output = []
        for line in iter(process.stdout.readline, ''):
            socketio.emit('log', {'msg': line.strip()})
            full_output.append(line.strip())
        
        # লগ ডাটাবেজে সেভ
        with sqlite3.connect(LOG_DB) as conn:
            conn.execute("INSERT INTO terminal_logs (username, command, output, time) VALUES (?,?,?,?)", 
                         (user, cmd, "\\n".join(full_output), time.ctime()))
        socketio.emit('log', {'msg': "--- Task Completed ---"})
    threading.Thread(target=run).start()

@socketio.on('save_and_run')
def handle_run(data):
    user, f_name, code = session.get('user'), data['filename'], data['code']
    path = os.path.join(PROJECT_DIR, f"{user}_{f_name}")
    
    # ফাইলে সেভ
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    
    # ডাটাবেজে সেভ
    with sqlite3.connect(USER_DB) as conn:
        conn.execute("INSERT INTO files (username, filename, code, time) VALUES (?,?,?,?)", 
                     (user, f_name, code, time.ctime()))
    
    def execute():
        proc = subprocess.Popen(['python', path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(proc.stdout.readline, ''):
            socketio.emit('log', {'msg': line.strip()})
    threading.Thread(target=execute).start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port)
