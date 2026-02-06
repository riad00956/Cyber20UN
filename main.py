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
import re

# Flask & SocketIO Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Threading mode for Render.com compatibility
socketio = SocketIO(app,
                   cors_allowed_origins="*",
                   transports=['websocket', 'polling'],
                   async_mode='threading',
                   ping_timeout=60,
                   ping_interval=25,
                   logger=False,
                   engineio_logger=False)

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
        print(f"🚀 Access Keys Generated:")
        print(f"🔑 Server URL: http://[YOUR_IP]:8000/?key={keys['server_key']}")
        print(f"🔑 Access URL: http://[YOUR_IP]:8000/access/{keys['access_key']}")
        print(f"🔑 Ghost URL: http://[YOUR_IP]:8000/ghost/{keys['ghost_key']}")
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
            # If file is corrupted, regenerate
            os.remove(SECRET_KEY_FILE)
            return generate_access_keys()

ACCESS_KEYS = generate_access_keys()

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS files 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            filename TEXT NOT NULL,
                            code TEXT,
                            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            # Create index only after table exists
            try:
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_files_username 
                               ON files(username, time DESC)''')
            except:
                pass  # Index might already exist
    
        # Terminal Logs Database
        with sqlite3.connect(LOG_DB) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS terminal_logs 
                           (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            command TEXT NOT NULL,
                            output TEXT,
                            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            # Create index only after table exists
            try:
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_logs_username_time 
                               ON terminal_logs(username, time DESC)''')
            except:
                pass  # Index might already exist
        
        print("✅ Databases initialized successfully")
        
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")
        # Continue anyway - tables might already exist

# Initialize databases
init_dbs()

# Safe command execution
ALLOWED_COMMANDS = {
    'ls', 'pwd', 'cd', 'cat', 'echo', 'python', 'python3',
    'pip', 'pip3', 'git', 'curl', 'wget', 'mkdir', 'rmdir',
    'cp', 'mv', 'find', 'grep', 'ps', 'whoami', 'date', 'uname',
    'touch', 'head', 'tail', 'wc', 'sort', 'uniq'
}

def is_safe_command(command):
    """Validate command for security"""
    if not command or len(command.strip()) == 0:
        return False
    
    cmd = command.strip().lower()
    
    # Dangerous commands
    dangerous = [
        'rm -rf', 'rm -fr', 'rm -f', 'rm -r',
        'dd if=', 'mkfs', 'chmod 777', 'chmod +x',
        'wget', 'curl', ':(){:|:&};:', 'fork',
        '> /dev/', '>> /dev/', '&> /dev/',
        'sudo', 'su ', 'passwd', 'shutdown', 'reboot',
        'halt', 'poweroff', 'init', 'killall',
        'pkill', 'kill -9', 'systemctl'
    ]
    
    for danger in dangerous:
        if danger in cmd:
            return False
    
    # Check allowed commands
    cmd_parts = cmd.split()
    if cmd_parts:
        base_cmd = cmd_parts[0]
        # Allow pip with install/uninstall
        if base_cmd == 'pip' or base_cmd == 'pip3':
            if len(cmd_parts) > 1:
                if cmd_parts[1] not in ['install', 'uninstall', 'list', 'show', 'freeze']:
                    return False
            return True
        # Allow python commands
        elif base_cmd in ['python', 'python3']:
            return True
        # Check other allowed commands
        elif base_cmd not in ALLOWED_COMMANDS:
            return False
    
    return True

# Safe filename validation
def is_safe_filename(filename):
    """Validate filename for security"""
    if not filename or len(filename) > 100:
        return False
    
    # Only allow alphanumeric, dots, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        return False
    
    # Prevent directory traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Prevent dangerous extensions
    dangerous_ext = ['.sh', '.exe', '.bat', '.cmd', '.js', '.php']
    for ext in dangerous_ext:
        if filename.endswith(ext):
            return False
    
    return True

# --- HTML Templates ---
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
        * { box-sizing: border-box; transition: all 0.3s ease; }
        body {
            margin: 0;
            font-family: 'Poppins', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }
        #bgCanvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.5;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 1;
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
        .card {
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
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
        input, textarea, select {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 15px;
            border-radius: 12px;
            width: 100%;
            font-family: 'Fira Code', monospace;
            margin-bottom: 15px;
            outline: none;
            font-size: 14px;
        }
        input:focus, textarea:focus, select:focus {
            border-color: var(--purple);
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }
        .btn {
            background: linear-gradient(45deg, var(--purple), var(--blue));
            color: white;
            border: none;
            padding: 16px 24px;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            font-size: 15px;
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(139, 92, 246, 0.4);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--border);
        }
        #terminal {
            background: #000;
            color: #a5f3fc;
            height: 300px;
            overflow-y: auto;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Fira Code', monospace;
            font-size: 13px;
            border: 1px solid var(--border);
            line-height: 1.5;
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
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
        }
        .logo-text {
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(to right, var(--purple), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .quick-commands {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 15px 0;
        }
        .quick-cmd-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            font-family: 'Fira Code', monospace;
        }
        .quick-cmd-btn:hover {
            background: rgba(139, 92, 246, 0.2);
            border-color: var(--purple);
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
        }
        .file-item:hover {
            background: rgba(139, 92, 246, 0.1);
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
        }
        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.3);
        }
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .card { padding: 20px; }
            #terminal { height: 250px; }
        }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
    <div class="container">
        {% if not logged_in %}
        <div class="card" style="margin-top: 50px; text-align: center;">
            <div style="display: flex; justify-content: center; margin-bottom: 20px;">
                <div class="cyber-logo">
                    <i data-lucide="terminal" color="white" width="24" height="24"></i>
                </div>
            </div>
            <h2 style="margin-bottom: 30px;">Cyber 20 UN Login</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required autocomplete="off">
                <input type="password" name="password" placeholder="Password" required autocomplete="off">
                <button type="submit" class="btn">
                    <i data-lucide="log-in" width="18" height="18"></i>
                    Initialize Session
                </button>
            </form>
            <p style="margin-top: 20px; font-size: 13px; color: var(--cyan);">
                Create new account or login with existing credentials
            </p>
        </div>
        {% else %}
        <div class="header">
            <div style="display: flex; align-items: center; gap: 15px;">
                <div class="cyber-logo">
                    <i data-lucide="terminal" color="white" width="24" height="24"></i>
                </div>
                <div>
                    <div class="logo-text">Cyber 20 UN</div>
                    <div style="font-size: 12px; color: var(--cyan);">Welcome, {{ username }}</div>
                </div>
            </div>
            <div id="statusIndicator" class="status-box">
                <i data-lucide="circle" width="12" height="12"></i>
                CONNECTING...
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top: 0; margin-bottom: 15px;">
                <i data-lucide="file-code" width="18" height="18"></i>
                Code Editor
            </h3>
            <input type="text" id="filename" placeholder="main.py" value="main.py">
            <textarea id="code" style="height:200px; font-size: 13px;" placeholder="# Write your Python code here...">print("Hello, Cyber 20 UN!")</textarea>
            <button onclick="runCode()" class="btn">
                <i data-lucide="play-circle" width="18" height="18"></i>
                Save & Execute
            </button>
            
            <div style="margin-top: 20px;">
                <h4 style="margin-bottom: 10px;">
                    <i data-lucide="folder" width="16" height="16"></i>
                    Your Files
                </h4>
                <div id="fileList" class="file-list">
                    <!-- Files will be loaded here -->
                </div>
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top: 0; margin-bottom: 15px;">
                <i data-lucide="terminal-square" width="18" height="18"></i>
                Live Terminal
            </h3>
            <div id="terminal"></div>
            
            <div class="quick-commands">
                <button class="quick-cmd-btn" onclick="runQuickCmd('ls -la')">ls -la</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('pwd')">pwd</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('python --version')">python --version</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('pip list')">pip list</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('whoami')">whoami</button>
                <button class="quick-cmd-btn" onclick="runQuickCmd('date')">date</button>
            </div>
            
            <div style="display: flex; gap: 10px; margin-top: 15px;">
                <input type="text" id="cmd" placeholder="Enter command..." style="margin-bottom:0" onkeypress="handleKeyPress(event)">
                <button onclick="sendCommand()" class="btn" style="width: auto; padding: 15px 25px;">
                    <i data-lucide="chevron-right" width="18" height="18"></i>
                </button>
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: var(--cyan);">
                Allowed: python, pip, git, system commands (safe mode)
            </div>
        </div>
        
        <button class="logout-btn" onclick="logout()">
            <i data-lucide="log-out" width="14" height="14"></i>
            Logout
        </button>
        {% endif %}
    </div>

    <script>
        // Initialize icons
        lucide.createIcons();
        
        // Background animation
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let particles = [];
        
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        
        class Particle {
            constructor() {
                this.reset();
            }
            reset() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.size = Math.random() * 3 + 1;
                this.speedX = Math.random() * 2 - 1;
                this.speedY = Math.random() * 2 - 1;
                this.color = Math.random() > 0.5 ? '#8b5cf6' : '#3b82f6';
                this.alpha = Math.random() * 0.3 + 0.1;
            }
            update() {
                this.x += this.speedX;
                this.y += this.speedY;
                
                if (this.x > canvas.width) this.x = 0;
                if (this.x < 0) this.x = canvas.width;
                if (this.y > canvas.height) this.y = 0;
                if (this.y < 0) this.y = canvas.height;
            }
            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fillStyle = this.color;
                ctx.globalAlpha = this.alpha;
                ctx.fill();
            }
        }
        
        function initParticles() {
            particles = [];
            for (let i = 0; i < 50; i++) {
                particles.push(new Particle());
            }
        }
        
        function animateParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            particles.forEach(particle => {
                particle.update();
                particle.draw();
            });
            requestAnimationFrame(animateParticles);
        }
        
        window.addEventListener('resize', () => {
            resizeCanvas();
            initParticles();
        });
        
        // Initialize
        resizeCanvas();
        initParticles();
        animateParticles();
        
        // Socket.IO connection
        const socket = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000
        });
        
        // Connection status
        socket.on('connect', () => {
            console.log('Connected to server');
            updateStatus('CONNECTED 🟢', 'success');
            addLog('Connected to Cyber 20 UN server', 'info');
            loadUserFiles();
        });
        
        socket.on('disconnect', () => {
            console.log('Disconnected from server');
            updateStatus('DISCONNECTED 🔴', 'error');
            addLog('Disconnected from server', 'warning');
        });
        
        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            updateStatus('ERROR ⚠️', 'error');
            addLog('Connection error: ' + error.message, 'error');
        });
        
        // Terminal logs
        socket.on('log', (data) => {
            addLog(data.msg, data.type || 'normal');
        });
        
        // Session restore
        socket.on('session_restore', (data) => {
            if (data.last_file) {
                document.getElementById('filename').value = data.last_file.filename;
                document.getElementById('code').value = data.last_file.code;
                addLog(`Restored: ${data.last_file.filename}`, 'info');
            }
        });
        
        // File list update
        socket.on('file_list', (data) => {
            updateFileList(data.files);
        });
        
        // Helper functions
        function updateStatus(text, type) {
            const statusEl = document.getElementById('statusIndicator');
            statusEl.innerHTML = `<i data-lucide="circle" width="12" height="12"></i> ${text}`;
            
            if (type === 'success') {
                statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                statusEl.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                statusEl.style.color = 'var(--success)';
            } else if (type === 'error') {
                statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
                statusEl.style.borderColor = 'rgba(239, 68, 68, 0.3)';
                statusEl.style.color = 'var(--error)';
            }
            
            lucide.createIcons();
        }
        
        function addLog(message, type = 'normal') {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'log-line';
            
            let icon = '';
            switch(type) {
                case 'cmd':
                    line.classList.add('cmd-line');
                    icon = '<span style="color: var(--success);">$</span> ';
                    break;
                case 'error':
                    line.classList.add('error-line');
                    icon = '<span style="color: var(--error);">✗</span> ';
                    break;
                case 'info':
                    line.classList.add('info-line');
                    icon = '<span style="color: var(--cyan);">ℹ</span> ';
                    break;
                case 'warning':
                    line.classList.add('warning-line');
                    icon = '<span style="color: var(--warning);">⚠</span> ';
                    break;
                default:
                    icon = '> ';
            }
            
            line.innerHTML = icon + message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function loadUserFiles() {
            socket.emit('get_files');
        }
        
        function updateFileList(files) {
            const fileListEl = document.getElementById('fileList');
            if (!files || files.length === 0) {
                fileListEl.innerHTML = '<div style="text-align: center; color: var(--cyan); padding: 20px;">No files yet</div>';
                return;
            }
            
            fileListEl.innerHTML = files.map(file => `
                <div class="file-item">
                    <div>
                        <i data-lucide="file-text" width="14" height="14" style="margin-right: 8px;"></i>
                        ${file.filename}
                        <span style="font-size: 11px; color: var(--cyan); margin-left: 10px;">
                            ${new Date(file.time).toLocaleDateString()}
                        </span>
                    </div>
                    <button onclick="loadFile('${file.filename}')" style="background: none; border: none; color: var(--cyan); cursor: pointer;">
                        <i data-lucide="folder-open" width="14" height="14"></i>
                    </button>
                </div>
            `).join('');
            
            lucide.createIcons();
        }
        
        function loadFile(filename) {
            fetch(`/api/file/${encodeURIComponent(filename)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('filename').value = data.filename;
                        document.getElementById('code').value = data.code;
                        addLog(`Loaded: ${data.filename}`, 'info');
                    } else {
                        addLog(`Error: ${data.error}`, 'error');
                    }
                })
                .catch(error => {
                    addLog(`Error loading file: ${error}`, 'error');
                });
        }
        
        function runCode() {
            const filename = document.getElementById('filename').value.trim();
            const code = document.getElementById('code').value;
            
            if (!filename) {
                addLog('Please enter a filename', 'error');
                return;
            }
            
            if (!code) {
                addLog('Please enter some code', 'error');
                return;
            }
            
            socket.emit('save_and_run', {filename: filename, code: code});
            addLog(`Running ${filename}...`, 'cmd');
        }
        
        function sendCommand() {
            const cmd = document.getElementById('cmd').value.trim();
            if (!cmd) {
                addLog('Please enter a command', 'error');
                return;
            }
            
            socket.emit('execute_command', {command: cmd});
            addLog(cmd, 'cmd');
            document.getElementById('cmd').value = '';
        }
        
        function runQuickCmd(cmd) {
            document.getElementById('cmd').value = cmd;
            sendCommand();
        }
        
        function handleKeyPress(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                sendCommand();
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        // Request session restore on page load
        window.addEventListener('load', () => {
            socket.emit('restore_session');
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
        # Get server statistics
        try:
            with sqlite3.connect(USER_DB) as conn:
                user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
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
        # Get active user count
        try:
            with sqlite3.connect(USER_DB) as conn:
                user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        except:
            user_count = 0
        
        # Calculate uptime
        uptime_seconds = int(time.time() - app_start_time)
        uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
        
        return render_template_string(GHOST_TEMPLATE,
                                     user_count=user_count,
                                     uptime=uptime_str,
                                     ghost_key=key[:8] + "..." + key[-8:])
    return "Invalid Ghost Key", 403

@app.route('/status')
def status():
    # Get server statistics
    try:
        with sqlite3.connect(USER_DB) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            file_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        
        with sqlite3.connect(LOG_DB) as conn:
            cmd_count = conn.execute("SELECT COUNT(*) FROM terminal_logs").fetchone()[0]
            last_cmd = conn.execute("SELECT command, time FROM terminal_logs ORDER BY time DESC LIMIT 1").fetchone()
    except:
        user_count = 0
        file_count = 0
        cmd_count = 0
        last_cmd = None
    
    return jsonify({
        'status': 'online',
        'server': 'Cyber 20 UN',
        'version': '2.0.0',
        'users': user_count,
        'files': file_count,
        'commands_executed': cmd_count,
        'uptime': time.time() - app_start_time,
        'uptime_human': str(datetime.utcfromtimestamp(time.time() - app_start_time).strftime('%Hh %Mm %Ss')),
        'timestamp': datetime.now().isoformat(),
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
    
    hashed_pwd = hash_password(p)
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
            if not user:
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?,?)", (u, hashed_pwd))
                except sqlite3.IntegrityError:
                    return "Username already exists", 409
            else:
                if user[2] != hashed_pwd:
                    return "Invalid credentials", 401
            
            session['user'] = u
            session.permanent = True
    except Exception as e:
        print(f"Login error: {e}")
        return "Server error", 500
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/api/file/<filename>')
def get_file(filename):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = session['user']
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            file_data = conn.execute(
                "SELECT filename, code FROM files WHERE username=? AND filename=? ORDER BY time DESC LIMIT 1",
                (user, filename)
            ).fetchone()
    except:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    
    if file_data:
        return jsonify({
            'success': True,
            'filename': file_data[0],
            'code': file_data[1]
        })
    
    return jsonify({'success': False, 'error': 'File not found'}), 404

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        user = session['user']
        emit('log', {'msg': f"✅ Connected to Cyber 20 UN", 'type': 'info'})
        emit('log', {'msg': f"👤 Welcome back, {user}", 'type': 'info'})
        
        # Send recent files
        try:
            with sqlite3.connect(USER_DB) as conn:
                files = conn.execute(
                    "SELECT filename, time FROM files WHERE username=? ORDER BY time DESC LIMIT 10",
                    (user,)
                ).fetchall()
                
                last_file = conn.execute(
                    "SELECT filename, code FROM files WHERE username=? ORDER BY time DESC LIMIT 1",
                    (user,)
                ).fetchone()
            
            emit('file_list', {'files': [
                {'filename': f[0], 'time': f[1]}
                for f in files
            ]})
            
            if last_file:
                emit('session_restore', {'last_file': {
                    'filename': last_file[0],
                    'code': last_file[1]
                }})
        except Exception as e:
            emit('log', {'msg': f"⚠️ Error loading files: {str(e)}", 'type': 'warning'})
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
                "SELECT filename, time FROM files WHERE username=? ORDER BY time DESC LIMIT 20",
                (user,)
            ).fetchall()
    except:
        files = []
    
    emit('file_list', {'files': [
        {'filename': f[0], 'time': f[1]}
        for f in files
    ]})

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
        emit('log', {'msg': 'Allowed: python, pip (install/uninstall), system commands', 'type': 'info'})
        return
    
    emit('log', {'msg': f'$ {cmd}', 'type': 'cmd'})
    
    def run_command():
        try:
            # Create user directory
            user_dir = os.path.join(PROJECT_DIR, user)
            os.makedirs(user_dir, exist_ok=True)
            
            # Prepare environment
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            # Split command for better handling
            if cmd.startswith('cd '):
                # Handle cd command separately
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
            
            full_output = []
            start_time = time.time()
            
            # Read output line by line
            while True:
                if process.stdout:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        line = output.rstrip('\n')
                        emit('log', {'msg': line, 'type': 'normal'})
                        full_output.append(line)
                
                # Timeout after 60 seconds
                if time.time() - start_time > 60:
                    process.terminate()
                    emit('log', {'msg': '⏰ Command timeout (60s)', 'type': 'error'})
                    break
            
            return_code = process.wait()
            
            if return_code == 0:
                emit('log', {'msg': '✅ Command completed successfully', 'type': 'info'})
            else:
                emit('log', {'msg': f'❌ Command failed with exit code {return_code}', 'type': 'error'})
            
            # Save to database
            try:
                with sqlite3.connect(LOG_DB) as conn:
                    conn.execute(
                        "INSERT INTO terminal_logs (username, command, output, time) VALUES (?,?,?,?)",
                        (user, cmd, "\n".join(full_output[:1000]), datetime.now().isoformat())
                    )
            except Exception as e:
                emit('log', {'msg': f'⚠️ Failed to save log: {str(e)}', 'type': 'warning'})
            
        except Exception as e:
            emit('log', {'msg': f'❌ Error: {str(e)}', 'type': 'error'})
    
    # Run in background thread
    threading.Thread(target=run_command, daemon=True).start()

@socketio.on('save_and_run')
def handle_run(data):
    if 'user' not in session:
        emit('log', {'msg': '❌ Please login first', 'type': 'error'})
        return
    
    user = session['user']
    f_name = data['filename'].strip()
    code = data['code']
    
    # Validate filename
    if not is_safe_filename(f_name):
        emit('log', {'msg': '❌ Invalid filename', 'type': 'error'})
        emit('log', {'msg': 'Use only letters, numbers, dots, underscores, and hyphens', 'type': 'info'})
        return
    
    # Validate code length
    if len(code) > 100000:  # 100KB limit
        emit('log', {'msg': '❌ Code too large (max 100KB)', 'type': 'error'})
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
        try:
            with sqlite3.connect(USER_DB) as conn:
                conn.execute(
                    "INSERT INTO files (username, filename, code, time) VALUES (?,?,?,?)",
                    (user, f_name, code, datetime.now().isoformat())
                )
        except Exception as e:
            emit('log', {'msg': f'⚠️ Failed to save to database: {str(e)}', 'type': 'warning'})
        
        emit('log', {'msg': f'💾 File saved: {f_name}', 'type': 'info'})
        
        # Update file list
        try:
            with sqlite3.connect(USER_DB) as conn:
                files = conn.execute(
                    "SELECT filename, time FROM files WHERE username=? ORDER BY time DESC LIMIT 10",
                    (user,)
                ).fetchall()
            
            emit('file_list', {'files': [
                {'filename': f[0], 'time': f[1]}
                for f in files
            ]})
        except:
            pass
        
        # Run Python file
        if f_name.endswith('.py'):
            def execute_python():
                try:
                    emit('log', {'msg': f'🚀 Running {f_name}...', 'type': 'cmd'})
                    
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
                    
                    for line in iter(process.stdout.readline, ''):
                        emit('log', {'msg': line.rstrip('\n'), 'type': 'normal'})
                    
                    process.wait()
                    emit('log', {'msg': '✅ Execution completed', 'type': 'info'})
                    
                except Exception as e:
                    emit('log', {'msg': f'❌ Execution error: {str(e)}', 'type': 'error'})
            
            threading.Thread(target=execute_python, daemon=True).start()
        else:
            emit('log', {'msg': f'📄 File saved (not a Python file, not executed)', 'type': 'info'})
    
    except Exception as e:
        emit('log', {'msg': f'❌ Error saving file: {str(e)}', 'type': 'error'})

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
        except:
            pass

# Global start time for uptime calculation
app_start_time = time.time()

# Run the application
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 CYBER 20 UN SERVER STARTING...")
    print("="*60)
    print(f"🔗 Server URL: http://0.0.0.0:8000/?key={ACCESS_KEYS['server_key']}")
    print(f"🔗 Access URL: http://0.0.0.0:8000/access/{ACCESS_KEYS['access_key']}")
    print(f"🔗 Ghost URL: http://0.0.0.0:8000/ghost/{ACCESS_KEYS['ghost_key']}")
    print("="*60)
    print("📁 Project Directory:", PROJECT_DIR)
    print("💾 Databases:", USER_DB, LOG_DB)
    print("⚡ Async Mode: threading")
    print("="*60 + "\n")
    
    port = int(os.environ.get('PORT', 8000))
    
    # Use development server for local, production for Render
    if os.environ.get('RENDER', 'false').lower() == 'true':
        # Production mode for Render
        socketio.run(app,
                    host='0.0.0.0',
                    port=port,
                    debug=False,
                    allow_unsafe_werkzeug=True)
    else:
        # Development mode
        socketio.run(app,
                    host='0.0.0.0',
                    port=port,
                    debug=True,
                    allow_unsafe_werkzeug=True)
