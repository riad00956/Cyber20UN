import os
import subprocess
import threading
import sqlite3
import hashlib
import secrets
import sys
import signal
import time
import json
from flask import Flask, render_template, request, session, redirect, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', transports=['polling'])

USER_DB = "cyber_vault.db"
PROJECT_DIR = os.path.abspath("user_projects")
os.makedirs(PROJECT_DIR, exist_ok=True)

# হোস্টিং প্রসেস ট্র্যাক করার ডিকশনারি
active_hosts = {}

def get_db():
    conn = sqlite3.connect(USER_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# ডাটাবেস সেটআপ
with get_db() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)')
    conn.execute('''CREATE TABLE IF NOT EXISTS files 
                   (username TEXT, filename TEXT, code TEXT, is_hosted INTEGER DEFAULT 0, 
                    port INTEGER DEFAULT 8080, PRIMARY KEY(username, filename))''')

def get_available_port(start_port=8080):
    """একটি খালি পোর্ট খুঁজে বের করে"""
    import socket
    port = start_port
    while port < 9000:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except OSError:
                port += 1
    return 8080

def stream_output(process, filename, user, port):
    """আউটপুট লাইভ টার্মিনালে পাঠানোর জন্য"""
    try:
        for line in iter(process.stdout.readline, ''):
            if line:
                msg = f"[{filename}] {line.strip()}"
                socketio.emit('log', {'msg': msg, 'type': 'output', 'port': port, 'filename': filename})
        process.stdout.close()
        return_code = process.wait()
        socketio.emit('log', {'msg': f"● Hosting stopped for '{filename}' (Exit code: {return_code})", 'type': 'info'})
        
        # হোস্টিং বন্ধ হলে ডাটাবেস আপডেট করুন
        with get_db() as conn:
            conn.execute("UPDATE files SET is_hosted=0 WHERE username=? AND filename=?", (user, filename))
        if (user, filename) in active_hosts:
            del active_hosts[(user, filename)]
    except Exception as e:
        socketio.emit('log', {'msg': f"Stream Error: {str(e)}", 'type': 'error'})

def stop_process(user, filename):
    key = (user, filename)
    if key in active_hosts:
        try:
            process_info = active_hosts[key]
            process = process_info['process']
            
            # প্রসেস গ্রুপ কিল করা
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except:
                process.terminate()
            
            # পোর্ট মুক্ত করুন
            socketio.emit('log', {'msg': f"● Stopped hosting for '{filename}'", 'type': 'info'})
            
            # ডাটাবেস আপডেট করুন
            with get_db() as conn:
                conn.execute("UPDATE files SET is_hosted=0 WHERE username=? AND filename=?", (user, filename))
            
            del active_hosts[key]
            
        except Exception as e:
            socketio.emit('log', {'msg': f"Stop Error: {str(e)}", 'type': 'error'})

def install_requirements(user, filename):
    """Python ফাইলের জন্য requirements.txt চেক করুন এবং প্রয়োজনীয় প্যাকেজ ইনস্টল করুন"""
    user_path = os.path.join(PROJECT_DIR, user)
    requirements_path = os.path.join(user_path, 'requirements.txt')
    
    if os.path.exists(requirements_path):
        try:
            socketio.emit('log', {'msg': f"📦 Installing dependencies from requirements.txt...", 'type': 'info'})
            process = subprocess.Popen(
                ["pip", "install", "-r", "requirements.txt", "--user"],
                cwd=user_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            for line in iter(process.stdout.readline, ''):
                if line:
                    socketio.emit('log', {'msg': f"[pip] {line.strip()}", 'type': 'output'})
            
            process.wait()
            socketio.emit('log', {'msg': f"✅ Dependencies installed successfully", 'type': 'info'})
            return True
        except Exception as e:
            socketio.emit('log', {'msg': f"❌ Dependency installation failed: {str(e)}", 'type': 'error'})
            return False
    return True

@app.route('/')
def index():
    if 'user' not in session:
        return render_template('index.html', logged_in=False)
    return render_template('index.html', logged_in=True, username=session['user'])

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username', '').lower().strip()
    p = request.form.get('password', '')
    if not u or not p:
        return jsonify({'error': 'Credentials required'}), 400
    
    hp = hashlib.sha256(p.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users VALUES (?,?)", (u, hp))
            session['user'] = u
            return jsonify({'success': True, 'message': 'Account created successfully'})
        elif user['password'] != hp:
            return jsonify({'error': 'Invalid credentials'}), 401
        else:
            session['user'] = u
            return jsonify({'success': True, 'message': 'Login successful'})

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        emit('log', {'msg': f"✅ Connected as {session['user']}", 'type': 'info'})

@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session:
        return
    user = session['user']
    cmd = data['command'].strip()
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    emit('log', {'msg': f"➜ {cmd}", 'type': 'cmd'})
    
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONPATH'] = user_path
    env['PATH'] = f"{user_path}/.local/bin:{env.get('PATH', '')}"

    try:
        process = subprocess.Popen(
            cmd, shell=True, cwd=user_path, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
            text=True, bufsize=1, universal_newlines=True,
            preexec_fn=os.setsid
        )
        threading.Thread(target=stream_output, args=(process, "CMD", user, 0)).start()
    except Exception as e:
        emit('log', {'msg': f"❌ Error: {str(e)}", 'type': 'error'})

@socketio.on('save_run')
def save_run(data):
    if 'user' not in session:
        return
    
    user = session['user']
    filename = data['filename'].strip()
    code = data['code']
    
    if not filename:
        emit('log', {'msg': '❌ Please provide a filename', 'type': 'error'})
        return
    
    if not filename.endswith('.py'):
        filename += '.py'
    
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    # ফাইল সেভ করুন
    filepath = os.path.join(user_path, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(code)
    
    # আগের হোস্টিং বন্ধ করুন
    stop_process(user, filename)
    
    # ডিপেন্ডেন্সি ইনস্টল করুন
    install_requirements(user, filename)
    
    # পোর্ট খুঁজে বের করুন
    port = get_available_port()
    
    # হোস্টিং শুরু করুন
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONPATH'] = user_path
    env['PORT'] = str(port)
    env['PATH'] = f"{user_path}/.local/bin:{env.get('PATH', '')}"

    try:
        # Flask অ্যাপের জন্য বিশেষ হ্যান্ডলিং
        if 'flask' in code.lower() or 'Flask(' in code:
            socketio.emit('log', {'msg': f"🚀 Detected Flask app - starting on port {port}", 'type': 'info'})
            process = subprocess.Popen(
                ["python3", "-u", filename],
                cwd=user_path, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, preexec_fn=os.setsid
            )
        else:
            process = subprocess.Popen(
                ["python3", "-u", filename],
                cwd=user_path, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, preexec_fn=os.setsid
            )
        
        active_hosts[(user, filename)] = {
            'process': process,
            'port': port,
            'started_at': time.time()
        }
        
        # ডাটাবেসে সেভ করুন
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?)", 
                        (user, filename, code, 1, port))
        
        emit('log', {'msg': f"🚀 '{filename}' is now hosted on port {port}", 'type': 'info'})
        emit('log', {'msg': f"📡 Access URL: http://localhost:{port} (if running locally)", 'type': 'info'})
        
        # আউটপুট স্ট্রিমিং শুরু করুন
        threading.Thread(target=stream_output, args=(process, filename, user, port)).start()
        
        # ফাইল লিস্ট আপডেট করুন
        list_files()
        
    except Exception as e:
        emit('log', {'msg': f"❌ Host Error: {str(e)}", 'type': 'error'})

@socketio.on('get_files')
def list_files():
    if 'user' not in session:
        return
    
    user = session['user']
    with get_db() as conn:
        files = conn.execute(
            "SELECT filename, is_hosted, port FROM files WHERE username=? ORDER BY filename",
            (user,)
        ).fetchall()
    
    # ডাটাবেসে HOSTED স্ট্যাটাস আপডেট করুন
    for file in files:
        filename = file['filename']
        if (user, filename) in active_hosts:
            conn.execute(
                "UPDATE files SET is_hosted=1 WHERE username=? AND filename=?",
                (user, filename)
            )
        else:
            conn.execute(
                "UPDATE files SET is_hosted=0 WHERE username=? AND filename=?",
                (user, filename)
            )
    
    # নতুন করে ডাটা ফেচ করুন
    files = conn.execute(
        "SELECT filename, is_hosted, port FROM files WHERE username=? ORDER BY filename",
        (user,)
    ).fetchall()
    
    emit('file_list', {
        'files': [{
            'name': f['filename'],
            'hosted': f['is_hosted'],
            'port': f['port'] if f['port'] else 0
        } for f in files]
    })

@socketio.on('load_file')
def load_file(data):
    if 'user' not in session:
        return
    
    user = session['user']
    filename = data['filename']
    
    with get_db() as conn:
        file = conn.execute(
            "SELECT * FROM files WHERE username=? AND filename=?",
            (user, filename)
        ).fetchone()
    
    if file:
        emit('file_data', {'filename': file['filename'], 'code': file['code']})
        emit('log', {'msg': f"📂 Loaded '{filename}'", 'type': 'info'})

@socketio.on('delete_file')
def delete_file(data):
    if 'user' not in session:
        return
    
    user = session['user']
    filename = data['filename']
    
    # হোস্টিং বন্ধ করুন
    stop_process(user, filename)
    
    # ফাইল ডিলিট করুন
    try:
        filepath = os.path.join(PROJECT_DIR, user, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
    except Exception as e:
        emit('log', {'msg': f"⚠️ File deletion error: {str(e)}", 'type': 'warning'})
    
    # ডাটাবেস থেকে ডিলিট করুন
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE username=? AND filename=?", (user, filename))
    
    emit('log', {'msg': f"🗑️ Deleted '{filename}'", 'type': 'info'})
    
    # ফাইল লিস্ট আপডেট করুন
    list_files()

@socketio.on('stop_hosting')
def stop_hosting(data):
    if 'user' not in session:
        return
    
    user = session['user']
    filename = data['filename']
    
    stop_process(user, filename)
    list_files()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 Server starting on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
