import os
import subprocess
import threading
import sqlite3
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber_ultra_secret_2026'
socketio = SocketIO(app, cors_allowed_origins="*", transports=['websocket'])

DB_PATH = "cyber_data.db"
PROJECT_DIR = "user_vault"

if not os.path.exists(PROJECT_DIR):
    os.makedirs(PROJECT_DIR)

# --- ডেটাবেজ লজিক ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, filename TEXT, code TEXT)''')
        conn.commit()

init_db()

# --- ফ্রন্টএন্ড (আপনার দেওয়া হুবহু UI + Dashboard Logic) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber 20 UN - Pro Cloud</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root {
            --bg: #020617; --purple: #8b5cf6; --blue: #3b82f6; --cyan: #06b6d4;
            --text: #f8fafc; --glass: rgba(15, 23, 42, 0.6); --border: rgba(255, 255, 255, 0.1);
        }
        .light-mode {
            --bg: #f1f5f9; --purple: #6366f1; --blue: #2563eb; --text: #0f172a;
            --glass: rgba(255, 255, 255, 0.7); --border: rgba(0, 0, 0, 0.1);
        }
        * { box-sizing: border-box; transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1); }
        body {
            margin: 0; font-family: 'Poppins', sans-serif; background: var(--bg);
            color: var(--text); min-height: 100vh; overflow-x: hidden;
            display: flex; flex-direction: column;
        }
        #bgCanvas { position: fixed; top: 0; left: 0; z-index: -1; filter: blur(2px); }
        .container { max-width: 850px; margin: auto; padding: 25px; width: 100%; position: relative; z-index: 1; }
        .logo-container { display: flex; align-items: center; gap: 12px; }
        .cyber-logo {
            width: 40px; height: 40px; background: linear-gradient(135deg, var(--purple), var(--blue));
            border-radius: 10px; display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.5); animation: logo-float 3s infinite;
        }
        @keyframes logo-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        .card {
            background: var(--glass); backdrop-filter: blur(20px); border: 1px solid var(--border);
            border-radius: 28px; padding: 30px; margin-bottom: 30px; box-shadow: 0 0 20px rgba(139, 92, 246, 0.1);
        }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .status-box { display: flex; align-items: center; gap: 10px; background: rgba(16, 185, 129, 0.1); padding: 6px 15px; border-radius: 50px; color: #10b981; font-size: 13px; }
        input, textarea { background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border); color: var(--text); padding: 16px; border-radius: 18px; width: 100%; font-family: 'Fira Code', monospace; margin-bottom: 20px; outline: none; }
        .btn { background: linear-gradient(45deg, var(--purple), var(--blue)); color: white; border: none; padding: 18px; border-radius: 18px; font-weight: 700; cursor: pointer; width: 100%; display: flex; align-items: center; justify-content: center; gap: 12px; font-size: 16px; }
        #terminal { background: #000; color: #a5f3fc; height: 240px; overflow-y: auto; padding: 18px; border-radius: 18px; font-family: 'Fira Code', monospace; font-size: 13px; border: 1px solid var(--border); }
        .file-item { display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.05); padding: 10px 20px; border-radius: 12px; margin-bottom: 10px; border: 1px solid var(--border); }
        .delete-btn { color: #ef4444; cursor: pointer; background: none; border: none; }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
    <div class="container">
        {% if not logged_in %}
        <div class="card" style="margin-top: 100px; text-align: center;">
            <div class="cyber-logo" style="margin: 0 auto 20px auto;"><i data-lucide="shield-check" color="white"></i></div>
            <h2>Cyber 20 Login</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="btn">Initialize Access</button>
            </form>
        </div>
        {% else %}
        <header class="header">
            <div class="logo-container">
                <div class="cyber-logo"><i data-lucide="terminal" color="white"></i></div>
                <h2 style="margin:0; background: linear-gradient(to right, var(--purple), var(--cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Cyber 20 UN</h2>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <span style="font-size: 12px; opacity: 0.7;">Hi, {{ username }}</span>
                <a href="/logout" style="color: var(--purple); font-size: 12px; text-decoration: none; border: 1px solid var(--purple); padding: 5px 10px; border-radius: 10px;">Logout</a>
            </div>
        </header>

        <main>
            <div class="card">
                <h3><i data-lucide="folder-code"></i> My Projects</h3>
                <div id="file-list">
                    {% for file in files %}
                    <div class="file-item" id="file-{{ file.id }}">
                        <span>{{ file.filename }}</span>
                        <button class="delete-btn" onclick="deleteFile({{ file.id }})"><i data-lucide="trash-2" size="18"></i></button>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="card">
                <div style="display:flex; align-items:center; gap:12px; margin-bottom:15px;">
                    <i data-lucide="code-2" style="color:var(--purple)"></i>
                    <input type="text" id="filename" placeholder="main.py" style="margin-bottom:0">
                </div>
                <textarea id="code" placeholder="# Code here..."></textarea>
                <button onclick="runCode(this)" class="btn" id="deploy-btn">
                    <i data-lucide="play-circle"></i> Save & Deploy
                </button>
            </div>

            <div class="card">
                <div id="terminal"></div>
                <div style="display: flex; gap: 12px; margin-top: 20px;">
                    <input type="text" id="cmd" placeholder="pip install library..." style="margin-bottom:0">
                    <button onclick="sendCommand(this)" class="btn" style="width:70px;"><i data-lucide="chevron-right"></i></button>
                </div>
            </div>
        </main>
        {% endif %}
    </div>

    <script>
        lucide.createIcons();
        const socket = io({transports: ['websocket']});

        // Background Logic
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let particles = [];
        function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
        window.onresize = resize; resize();
        class Ball {
            constructor() { this.reset(); }
            reset() { this.x = Math.random() * canvas.width; this.y = -50; this.r = Math.random() * 5 + 2; this.speed = Math.random() * 2 + 0.5; this.color = Math.random() > 0.5 ? '#8b5cf6' : '#3b82f6'; }
            update() { this.y += this.speed; if (this.y > canvas.height + 50) this.reset(); }
            draw() { ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2); ctx.fillStyle = this.color; ctx.globalAlpha = 0.2; ctx.fill(); }
        }
        for(let i=0; i<35; i++) particles.push(new Ball());
        function loop() { ctx.clearRect(0,0, canvas.width, canvas.height); particles.forEach(p => { p.update(); p.draw(); }); requestAnimationFrame(loop); }
        loop();

        // Terminal & File Logic
        socket.on('log', (msg) => {
            const term = document.getElementById('terminal');
            term.innerHTML += `<div>> ${msg}</div>`;
            term.scrollTop = term.scrollHeight;
        });

        function runCode(btn) {
            const filename = document.getElementById('filename').value || 'main.py';
            const code = document.getElementById('code').value;
            btn.innerHTML = 'Deploying...';
            socket.emit('save_and_run', {filename, code});
            setTimeout(() => { btn.innerHTML = '<i data-lucide="play-circle"></i> Save & Deploy'; lucide.createIcons(); }, 1500);
        }

        function sendCommand() {
            const cmd = document.getElementById('cmd').value;
            socket.emit('execute_command', {command: cmd});
            document.getElementById('cmd').value = '';
        }

        function deleteFile(id) {
            if(confirm("Delete this project?")) {
                fetch(`/delete/${id}`, {method: 'POST'}).then(res => {
                    if(res.ok) document.getElementById(`file-${id}`).remove();
                });
            }
        }
    </script>
</body>
</html>
"""

# --- সার্ভার রাউটস ---
@app.route('/')
def index():
    if 'user' not in session:
        return render_template_string(HTML_TEMPLATE, logged_in=False)
    
    with get_db() as conn:
        files = conn.execute("SELECT * FROM files WHERE username = ?", (session['user'],)).fetchall()
    
    return render_template_string(HTML_TEMPLATE, logged_in=True, username=session['user'], files=files)

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('username')
    pw = request.form.get('password')
    
    with get_db() as conn:
        db_user = conn.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
        if db_user:
            if db_user['password'] == pw:
                session['user'] = user
            else: return "Wrong Password", 401
        else:
            conn.execute("INSERT INTO users (username, password) VALUES (?,?)", (user, pw))
            conn.commit()
            session['user'] = user
            
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user' not in session: return "Unauthorized", 403
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE id = ? AND username = ?", (file_id, session['user']))
        conn.commit()
    return "OK", 200

# --- সকেট ইভেন্ট (লাইব্রেরি এবং কোড রান) ---
@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    cmd = data['command']
    def run():
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            socketio.emit('log', line.strip())
        socketio.emit('log', "--- Process End ---")
    threading.Thread(target=run).start()

@socketio.on('save_and_run')
def handle_run(data):
    if 'user' not in session: return
    user = session['user']
    filename = data['filename']
    code = data['code']
    
    with get_db() as conn:
        conn.execute("INSERT INTO files (username, filename, code) VALUES (?,?,?)", (user, filename, code))
        conn.commit()
    
    path = os.path.join(PROJECT_DIR, f"{user}_{filename}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    
    def execute():
        proc = subprocess.Popen(['python', path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            socketio.emit('log', line.strip())
    threading.Thread(target=execute).start()

if __name__ == '__main__':
    # Render এর জন্য ডাইনামিক পোর্ট
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
