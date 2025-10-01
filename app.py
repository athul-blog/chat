from flask import Flask, render_template, request, redirect, session, jsonify, url_for, send_from_directory, Response
from flask_bcrypt import Bcrypt
import json
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # CHANGE THIS in production (use env var)
bcrypt = Bcrypt(app)

# In-memory message stores (not persisted)
messages = []  # list of {'user': username, 'text': text}
private_messages = {}  # { (user1, user2): [ { 'user': sender, 'text': text }, ... ] }

# File upload config
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Persisted data files
USERS_FILE = 'users.json'
PENDING_FILE = 'pending_users.json'
USER_UI_FILE = 'user_ui.json'
ENTRY_LOGS_FILE = 'entry_logs.json'

# ---------------- Helpers ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_json_file(path, default):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(default, f, indent=4)
        return default
    with open(path, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default

def save_json_file(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def log_entry(username, ip):
    logs = load_json_file(ENTRY_LOGS_FILE, [])
    timestamp = datetime.utcnow().isoformat()

    logs.append({
        'username': username,
        'ip': ip,
        'timestamp': timestamp
    })

    save_json_file(ENTRY_LOGS_FILE, logs)

def count_entries_for_user(username):
    logs = load_json_file(ENTRY_LOGS_FILE, [])
    return sum(1 for entry in logs if entry.get('username') == username)

# ------------- Users helpers -------------
def load_users():
    return load_json_file(USERS_FILE, [])

def save_users(users):
    save_json_file(USERS_FILE, users)

def get_user(username):
    users = load_users()
    for u in users:
        if u.get('username') == username:
            return u
    return None

@app.context_processor
def utility_processor():
    return dict(get_user=get_user)

# ------------- Pending users helpers -------------
def load_pending_users():
    return load_json_file(PENDING_FILE, [])

def save_pending_users(pending):
    save_json_file(PENDING_FILE, pending)

# ------------- User UI helpers -------------
def load_user_ui():
    return load_json_file(USER_UI_FILE, {})

def save_user_ui(data):
    save_json_file(USER_UI_FILE, data)

# ---------------- Routes ----------------
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    ip = request.remote_addr
    log_entry(username, ip)

    user_ui = load_user_ui()
    custom_html = user_ui.get(username)
    if custom_html:
        return Response(custom_html, mimetype='text/html')

    users = load_users()
    usernames = [u['username'] for u in users if u['username'] != username]
    entry_count = count_entries_for_user(username)
    return render_template('index.html', username=username, users=usernames, entry_count=entry_count)

# ---------------- Auth: Login/Register ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = get_user(username)
        if user and user.get('password_hash') and bcrypt.check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect(url_for('home'))
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        bio = request.form.get('bio', '').strip()

        if not username or not password:
            return render_template('register.html', error='All fields required')

        if get_user(username):
            return render_template('register.html', error='Username already exists')

        pending = load_pending_users()
        if any(u['username'] == username for u in pending):
            return render_template('register.html', error='Username pending approval')

        pending.append({
            'username': username,
            'password_hash': bcrypt.generate_password_hash(password).decode('utf-8'),
            'bio': bio,
            'avatar': ''
        })
        save_pending_users(pending)
        return render_template('register.html', success='Account request sent, wait for approval')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# ---------------- Messages (public) ----------------
@app.route('/messages', methods=['GET', 'POST'])
def handle_messages():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'POST':
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get('text') or '').strip()
        if text:
            messages.append({'user': session['username'], 'text': text})
            return jsonify({'status': 'ok'}), 201
        return jsonify({'error': 'No text provided'}), 400
    return jsonify(messages)

# ---------------- Avatar upload ----------------
@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"{session['username']}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        users = load_users()
        for u in users:
            if u['username'] == session['username']:
                u['avatar'] = filename
        save_users(users)
        return jsonify({'status': 'ok', 'filename': filename})
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/avatars/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------- Private chat ----------------
@app.route('/private_chat/<recipient>')
def private_chat(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))
    sender = session['username']
    if recipient == sender:
        return "Can't chat with yourself!", 400
    if not get_user(recipient):
        return "User not found", 404
    return render_template('private_chat.html', username=sender, recipient=recipient)

@app.route('/private_messages/<recipient>', methods=['GET', 'POST'])
def private_messages_route(recipient):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    sender = session['username']
    if recipient == sender:
        return jsonify({'error': "Can't chat with yourself"}), 400
    if not get_user(recipient):
        return jsonify({'error': "Recipient not found"}), 404

    chat_key = tuple(sorted([sender, recipient]))
    if request.method == 'POST':
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get('text') or '').strip()
        if text:
            private_messages.setdefault(chat_key, []).append({'user': sender, 'text': text})
            return jsonify({'status': 'ok'}), 201
        return jsonify({'error': 'No text provided'}), 400
    return jsonify(private_messages.get(chat_key, []))

# ---------------- Profile routes ----------------
@app.route('/profile/<username>')
def profile(username):
    user = get_user(username)
    if not user:
        return "User not found", 404
    user_messages = [m for m in messages if m.get('user') == username]
    private_msgs = []
    for participants, msgs in private_messages.items():
        if username in participants:
            private_msgs.extend(msgs)
    entry_count = count_entries_for_user(username)
    return render_template('profile.html', user=user, public_msgs=user_messages, private_msgs=private_msgs, entry_count=entry_count)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = get_user(username)
    if not user:
        return "User not found", 404
    if request.method == 'POST':
        new_bio = request.form.get('bio', '').strip()
        users = load_users()
        for u in users:
            if u['username'] == username:
                u['bio'] = new_bio
        save_users(users)
        return redirect(url_for('profile', username=username))
    return render_template('edit_profile.html', user=user)

# ---------------- Admin UI override ----------------
@app.route('/admin/get_user_ui')
def admin_get_user_ui():
    if session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(load_user_ui())

@app.route('/admin/set_user_ui', methods=['POST'])
def admin_set_user_ui():
    if session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.form.get('username', '').strip()
    html = request.form.get('html', '')
    if not username:
        return jsonify({'error': 'username required'}), 400
    data = load_user_ui()
    data[username] = html
    save_user_ui(data)
    return jsonify({'status': 'ok'})

@app.route('/admin/remove_user_ui', methods=['POST'])
def admin_remove_user_ui():
    if session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'error': 'username required'}), 400
    data = load_user_ui()
    if username in data:
        del data[username]
        save_user_ui(data)
        return jsonify({'status': 'removed'})
    return jsonify({'status': 'not found'}), 404

# ---------------- Admin pending user approval ----------------
@app.route('/admin/pending_users')
def admin_pending_users():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    return render_template('pending_users.html', pending=load_pending_users())

@app.route('/admin/approve_user', methods=['POST'])
def admin_approve_user():
    if session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.form.get('username')
    pending = load_pending_users()
    user = next((u for u in pending if u['username'] == username), None)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    users = load_users()
    if any(u['username'] == username for u in users):
        pending = [u for u in pending if u['username'] != username]
        save_pending_users(pending)
        return jsonify({'error': 'Already exists'}), 400

    users.append(user)
    save_users(users)
    pending = [u for u in pending if u['username'] != username]
    save_pending_users(pending)
    return jsonify({'status': 'approved'})

@app.route('/admin/reject_user', methods=['POST'])
def admin_reject_user():
    if session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.form.get('username')
    pending = load_pending_users()
    pending = [u for u in pending if u['username'] != username]
    save_pending_users(pending)
    return jsonify({'status': 'rejected'})

@app.route('/users')
def list_users():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    users = load_users()
    return jsonify([{'username': u['username'], 'avatar': u.get('avatar', ''), 'bio': u.get('bio', '')} for u in users])

# ---------------- Run ------------------
if __name__ == '__main__':

    app.run(host="0.0.0.0", port=80) 

#Talvibe : Talk better , Vibe deeper
#Created by Athul vinod .M , published in 1-10-2025
