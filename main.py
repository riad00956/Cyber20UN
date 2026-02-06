import os
import subprocess
import threading
import sqlite3
import time
from flask import Flask, render_template_string, request, session, redirect, url_for
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber_20_un_pro_2026'
socketio = SocketIO(app, cors_allowed_origins="*", transports=['websocket'])

DB_PATH = "cyber_vault.db"

# --- ডাটাবেজ ফাংশন (সবকিছু এখানে সেভ হবে) ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # ইউজার টেবিল
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
        # ফাইল টেবিল
        conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, username TEXT, filename TEXT, code TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        # টার্মিনাল লগ টেবিল (লাইভ লগের জন্য)
        conn.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, username TEXT, command TEXT, output TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        conn.commit()

init_db()

# --- আপনার অরিজিনাল UI + লাইভ লগিং স্ক্রিপ্ট ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber 20 UN - Enterprise IDE</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        :root { --bg: #020617; --purple: #8b5cf6; --cyan: #06b6d4; --text: #f8fafc; --glass: rgba(15, 23, 42, 0.7); --border: rgba(255, 255, 255, 0.1); }
        body { margin: 0; font-family: 'Poppins', sans-serif; background: var(--bg); color: var(--text); overflow-x: hidden; }
        #bgCanvas { position: fixed; top: 0; left: 0; z-index: -1; }
        .container { max-width: 900px; margin: auto; padding: 20px; position: relative; z-index: 1; }
        .card { background: var(--glass); backdrop-filter: blur(15px); border-radius: 25px; padding: 25px; border: 1px solid var(--border); margin-bottom: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .cyber-logo { width: 45px; height: 45px; background: linear-gradient(135deg, var(--purple), var(--cyan)); border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(139,92,246,0.4); }
        input, textarea { background: rgba(0,0,0,0.3); border: 1px solid var(--border); color: #fff; padding: 15px; border-radius: 15px; width: 100%; font-family: 'Fira Code', monospace; margin-bottom: 15px; outline: none; }
        .btn { background: linear-gradient(45deg, var(--purple), #3b82f6); color: white; border: none; padding: 15px; border-radius: 15px; font-weight: 700; cursor: pointer; width: 100%; display: flex; align-items: center; justify-content: center; gap: 10px; }
        #terminal { background: #000; color: #10b981; height: 300px; overflow-y: auto; padding: 15px; border-radius: 15px; font-family: 'Fira Code', monospace; font-size: 13px; border: 1px solid #333; }
        .log-line { border-left: 2px solid var(--purple); padding-left: 10px; margin-bottom: 5px; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
    <div class="container">
        {% if not logged_in %}
        <div class="card" style="margin-top: 100px; text-align: center;">
            <h2>CYBER 20 LOGIN</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="User ID" required>
                <input type="password" name="password" placeholder="Key" required>
                <button type="submit" class="btn">ACCESS SERVER</button>
            </form>
        </div>
        {% else %}
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div style="display:flex; align-items:center; gap:15px;">
                <div class="cyber-logo"><i data-lucide="terminal" color="white"></i></div>
                <h2 style="margin:0; letter-spacing: 1px; color: var(--cyan);">CYBER 20 UN</h2>
            </div>
            <a href="/logout" style="color: #ef4444; text-decoration: none;">LOGOUT</a>
        </div>

        <div class="card">
            <input type="text" id="filename" placeholder="app.py" value="main.py">
            <textarea id="code" style="height: 150px;" placeholder="# Enter Python Code..."></textarea>
            <button onclick="runCode()" class="btn"><i data-lucide="zap"></i> SAVE & DEPLOY</button>
        </div>

        <div class="card">
            <div id="terminal"></div>
            <div style="display: flex; gap: 10px; margin-top: 15px;">
                <input type="text" id="cmd" placeholder="pip install requests..." style="margin-bottom:0">
                <button onclick="sendCommand()" class="btn" style="width: 70px;"><i data-lucide="chevron-right"></i></button>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        lucide.createIcons();
        const socket = io({transports: ['websocket']});
        const term = document.getElementById('terminal');

        // Animated Background (Falling Balls)
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let particles = [];
        function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
        window.onresize = resize; resize();
        class Particle {
            constructor() { this.reset(); }
            reset() { this.x = Math.random() * canvas.width; this.y = -20; this.r = Math.random() * 4 + 2; this.speed = Math.random() * 2 + 0.5; }
            update() { this.y += this.speed; if(this.y > canvas.height) this.reset(); }
            draw() { ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI*2); ctx.fillStyle = '#8b5cf6'; ctx.globalAlpha = 0.2; ctx.fill(); }
        }
        for(let i=0; i<30; i++) particles.push(new Particle());
        function animate() { ctx.clearRect(0,0,canvas.width,canvas.height); particles.forEach(p => { p.update(); p.draw(); }); requestAnimationFrame(animate); }
        animate();

        // Terminal logic
        socket.on('log', (data) => {
            const div = document.createElement('div');
            div.className = 'log-line';
            div.textContent = data.msg;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        });

        function runCode() {
            const f = document.getElementById('filename').value;
            const c = document.getElementById('code').value;
            term.innerHTML += `<div class="log-line" style="color:var(--cyan)">[System] Deploying ${f}...</div>`;
            socket.emit('save_and_run', {filename: f, code: c});
        }

        function sendCommand() {
            const cmd = document.getElementById('cmd').value;
            if(!cmd) return;
            term.innerHTML += `<div class="log-line" style="color:#f59e0b">$ ${cmd}</div>`;
            socket.emit('execute_command', {command: cmd});
            document.getElementById('cmd').value = '';
        }
    </script>
</body>
</html>
"""

# --- সার্ভার লজিক ---

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, logged_in='user' in session, username=session.get('user'))

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form.get('username'), request.form.get('password')
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, password) VALUES (?,?)", (u, p))
            conn.commit()
        session['user'] = u
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# রিয়েল টাইম লগ এবং ডাটাবেজ সেভিং
def log_to_db(user, cmd, output):
    with get_db() as conn:
        conn.execute("INSERT INTO logs (username, command, output) VALUES (?,?,?)", (user, cmd, output))
        conn.commit()

@socketio.on('execute_command')
def handle_command(data):
    user, cmd = session.get('user'), data['command']
    def run():
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        full_output = []
        for line in proc.stdout:
            socketio.emit('log', {'msg': line.strip()})
            full_output.append(line.strip())
        log_to_db(user, cmd, "\\n".join(full_output))
    threading.Thread(target=run).start()

@socketio.on('save_and_run')
def handle_run(data):
    user = session.get('user')
    filename, code = data['filename'], data['code']
    with get_db() as conn:
        conn.execute("INSERT INTO files (username, filename, code) VALUES (?,?,?)", (user, filename, code))
        conn.commit()
    
    # টেম্পোরারি ফাইলে সেভ করে রান করা
    temp_path = f"temp_{user}_{filename}"
    with open(temp_path, "w") as f: f.write(code)
    
    def run_py():
        proc = subprocess.Popen(['python', temp_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            socketio.emit('log', {'msg': line.strip()})
    threading.Thread(target=run_py).start()

if __name__ == '__main__':
    # Render Port
    port = int(os.environ.get('PORT', 8000))
    # host='0.0.0.0' দিলে আপনি যেকোনো ডোমেইন বা আইপি দিয়ে এক্সেস করতে পারবেন
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
