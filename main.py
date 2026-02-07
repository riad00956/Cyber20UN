import os
import subprocess
import threading
import sqlite3
import hashlib
import secrets
import sys
import signal
import time
from flask import Flask, render_template, request, session, redirect, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
# Render.com-এ স্ট্যাবিলিটির জন্য পোলিং মোড ব্যবহার করা হয়েছে
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
                    PRIMARY KEY(username, filename))''')

# --- ইঞ্জিন ফাংশনস ---

def stream_output(process, filename, user_session_id):
    """আউটপুট লাইভ টার্মিনালে পাঠানোর জন্য জেনারেটর"""
    # আউটপুট বাফারিং এড়াতে এবং রিয়েল টাইম ডাটা পাঠাতে এটি ব্যবহৃত হয়
    for line in iter(process.stdout.readline, ''):
        if line:
            msg = f"[{filename}] {line.strip()}" if filename else line.strip()
            # socketio.emit সরাসরি ব্যবহার করা হয়েছে যাতে লাইভ ডাটা যায়
            socketio.emit('log', {'msg': msg, 'type': 'output'})
    
    process.stdout.close()
    return_code = process.wait()
    if filename:
        socketio.emit('log', {'msg': f"● Hosting Process '{filename}' exited with code {return_code}", 'type': 'info'})

def stop_process(user, filename):
    key = (user, filename)
    if key in active_hosts:
        try:
            # প্রসেস গ্রুপ কিল করা যাতে চাইল্ড প্রসেসগুলোও বন্ধ হয়
            os.killpg(os.getpgid(active_hosts[key].pid), signal.SIGTERM)
            del active_hosts[key]
        except:
            if key in active_hosts: del active_hosts[key]

# --- রুটস (Routes) ---

@app.route('/')
def index():
    if 'user' not in session: return render_template('index.html', logged_in=False)
    return render_template('index.html', logged_in=True, username=session['user'])

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username', '').lower().strip()
    p = request.form.get('password', '')
    if not u or not p: return "Credentials required", 400
    
    hp = hashlib.sha256(p.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not user:
            conn.execute("INSERT INTO users VALUES (?,?)", (u, hp))
        elif user['password'] != hp:
            return "Login Failed", 401
    session['user'] = u
    return redirect('/')

# --- সকেট ইভেন্টস (Socket Events) ---

@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command'].strip()
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    emit('log', {'msg': cmd, 'type': 'cmd'})
    
    # লাইব্রেরি ইন্সটল করার সময় যাতে সেটি সাথে সাথে পাওয়া যায়
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1' # পাইথন আউটপুট আনবাফার্ড রাখা
    env['PYTHONPATH'] = user_path

    try:
        process = subprocess.Popen(
            cmd, shell=True, cwd=user_path, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
            text=True, bufsize=1, universal_newlines=True
        )
        # আলাদা থ্রেডে আউটপুট রিড করা যাতে মেইন সার্ভার হ্যাং না হয়
        threading.Thread(target=stream_output, args=(process, None, None)).start()
    except Exception as e:
        emit('log', {'msg': f"Error: {str(e)}", 'type': 'error'})

@socketio.on('save_run')
def save_run(data):
    if 'user' not in session: return
    user, filename, code = session['user'], data['filename'], data['code']
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    # সেভ করা
    with open(os.path.join(user_path, filename), 'w', encoding='utf-8') as f:
        f.write(code)
    
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?)", (user, filename, code, 1))
    
    # আগের হোস্টিং বন্ধ করা
    stop_process(user, filename)
    
    # নতুন করে হোস্ট করা
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONPATH'] = user_path

    try:
        # python3 -u ব্যবহার করা হয়েছে লাইভ আউটপুটের জন্য
        process = subprocess.Popen(
            ["python3", "-u", filename],
            cwd=user_path, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, preexec_fn=os.setsid
        )
        active_hosts[(user, filename)] = process
        emit('log', {'msg': f"🚀 {filename} is now hosted!", 'type': 'info'})
        threading.Thread(target=stream_output, args=(process, filename, None)).start()
    except Exception as e:
        emit('log', {'msg': f"Host Error: {str(e)}", 'type': 'error'})

@socketio.on('get_files')
def list_files():
    if 'user' not in session: return
    with get_db() as conn:
        files = conn.execute("SELECT filename, is_hosted FROM files WHERE username=?", (session['user'],)).fetchall()
    emit('file_list', {'files': [{'name': f['filename'], 'hosted': f['is_hosted']} for f in files]})

@socketio.on('load_file')
def load_file(data):
    if 'user' not in session: return
    with get_db() as conn:
        file = conn.execute("SELECT * FROM files WHERE username=? AND filename=?", (session['user'], data['filename'])).fetchone()
    if file: emit('file_data', {'filename': file['filename'], 'code': file['code']})

@socketio.on('delete_file')
def delete_file(data):
    if 'user' not in session: return
    user, filename = session['user'], data['filename']
    stop_process(user, filename)
    try: os.remove(os.path.join(PROJECT_DIR, user, filename))
    except: pass
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE username=? AND filename=?", (user, filename))
    emit('log', {'msg': f"Removed deployment: {filename}", 'type': 'info'})
    list_files()

if __name__ == '__main__':
    # Render.com-এর জন্য পোর্ট ১০০০০ ব্যবহার করা ভালো
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
