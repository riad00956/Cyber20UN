import os
import subprocess
import threading
import sqlite3
import hashlib
import secrets
import sys
import signal
from flask import Flask, render_template, request, session, redirect, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', transports=['polling'])

USER_DB = "cyber_vault.db"
PROJECT_DIR = os.path.abspath("user_projects")
os.makedirs(PROJECT_DIR, exist_ok=True)

# হোস্টিং প্রসেসগুলো ট্র্যাক করার জন্য ডিকশনারি
# {(username, filename): subprocess_object}
active_hosts = {}

def get_db():
    conn = sqlite3.connect(USER_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# Database setup - added 'is_hosted' column
with get_db() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)')
    conn.execute('''CREATE TABLE IF NOT EXISTS files 
                   (username TEXT, filename TEXT, code TEXT, is_hosted INTEGER DEFAULT 0, 
                    PRIMARY KEY(username, filename))''')

# --- Hosting Core Logic ---

def stop_process(user, filename):
    """ব্যাকগ্রাউন্ডে চলতে থাকা প্রসেস বন্ধ করার ফাংশন"""
    key = (user, filename)
    if key in active_hosts:
        try:
            # Linux/Unix-এ প্রসেস গ্রুপ বন্ধ করা
            os.killpg(os.getpgid(active_hosts[key].pid), signal.SIGTERM)
            del active_hosts[key]
            socketio.emit('log', {'msg': f'Stopped: {filename}', 'type': 'info'})
        except:
            if key in active_hosts: del active_hosts[key]

def start_hosting(user, filename, user_path):
    """ফাইলটিকে ব্যাকগ্রাউন্ডে হোস্ট করার ফাংশন"""
    # আগের প্রসেস থাকলে বন্ধ করা
    stop_process(user, filename)
    
    socketio.emit('log', {'msg': f'🚀 Hosting Started: {filename}', 'type': 'info'})
    
    def run():
        try:
            # start_new_session=True ব্যবহার করা হয়েছে যাতে মেইন অ্যাপ বন্ধ না হলেও এটি চলতে পারে
            process = subprocess.Popen(
                ["python3", "-u", filename], # -u for unbuffered output
                cwd=user_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid 
            )
            
            active_hosts[(user, filename)] = process
            
            for line in iter(process.stdout.readline, ''):
                if line:
                    socketio.emit('log', {'msg': f'[{filename}] {line.strip()}', 'type': 'output'})
            
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            socketio.emit('log', {'msg': f'Host Error ({filename}): {str(e)}', 'type': 'error'})

    threading.Thread(target=run, daemon=True).start()

# --- Routes ---

@app.route('/')
def index():
    if 'user' not in session: return render_template('index.html', logged_in=False)
    return render_template('index.html', logged_in=True, username=session['user'])

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

# --- Socket Operations ---

@socketio.on('execute_command')
def handle_command(data):
    if 'user' not in session: return
    user = session['user']
    cmd = data['command']
    user_path = os.path.join(PROJECT_DIR, user)
    
    socketio.emit('log', {'msg': f'user@{user}:~$ {cmd}', 'type': 'cmd'})
    
    def run_cmd():
        proc = subprocess.Popen(cmd, shell=True, cwd=user_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(proc.stdout.readline, ''):
            socketio.emit('log', {'msg': line.strip(), 'type': 'output'})
        proc.wait()
    threading.Thread(target=run_cmd).start()

@socketio.on('save_run')
def save_run(data):
    if 'user' not in session: return
    user, filename, code = session['user'], data['filename'], data['code']
    user_path = os.path.join(PROJECT_DIR, user)
    os.makedirs(user_path, exist_ok=True)
    
    # Disk-এ সেভ করা
    with open(os.path.join(user_path, filename), 'w', encoding='utf-8') as f:
        f.write(code)
    
    # DB-তে সেভ করা এবং হোস্ট স্ট্যাটাস আপডেট করা
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?)", (user, filename, code, 1))
    
    # হোস্টিং ইঞ্জিন চালু করা
    start_hosting(user, filename, user_path)

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
    
    # ১. ব্যাকগ্রাউন্ড প্রসেস বন্ধ করা
    stop_process(user, filename)
    
    # ২. ডিস্ক থেকে ফাইল মোছা
    try: os.remove(os.path.join(PROJECT_DIR, user, filename))
    except: pass
    
    # ৩. ডেটাবেস থেকে মোছা
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE username=? AND filename=?", (user, filename))
    
    list_files()
    emit('log', {'msg': f'Deleted & Unhosted: {filename}', 'type': 'info'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
