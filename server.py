from flask import Flask, request, jsonify, session, g, send_from_directory
import os
import sqlite3
import bcrypt
from datetime import timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to a secure random value
app.config['DATABASE'] = os.path.join(app.root_path, 'database.db')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database helper to get connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# API endpoint for registration
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400
    db = get_db()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        db.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
        return jsonify({"status": "ok", "message": "Registration successful"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 400

# API endpoint for login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password']):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({"status": "ok", "message": "Logged in successfully"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# API endpoint for logout
@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"status": "ok", "message": "Logged out"})

# API endpoint for file upload (expects multipart/form-data)
@app.route('/api/upload_file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    encrypted_filename = request.form.get('encrypted_filename')
    stored_filename = request.form.get('stored_filename')
    file_extension = request.form.get('file_extension', '')  # New field for file extension
    if not encrypted_filename or not stored_filename:
        return jsonify({"status": "error", "message": "Missing encrypted filename or stored filename"}), 400

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"}), 400

    # Use secure_filename for safety; stored_filename is already random
    stored_filename = secure_filename(stored_filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    file.save(filepath)

    db = get_db()
    db.execute(
        "INSERT INTO files (owner_id, encrypted_original_filename, stored_filename, file_extension) VALUES (?, ?, ?, ?)",
        (session['user_id'], encrypted_filename, stored_filename, file_extension)
    )
    db.commit()
    return jsonify({"status": "ok", "message": "File uploaded successfully"})

# API endpoint to list files for the logged-in user
@app.route('/api/list_files', methods=['GET'])
def list_files():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    db = get_db()
    files = db.execute("SELECT id, encrypted_original_filename, stored_filename, file_extension FROM files WHERE owner_id = ?",
                       (session['user_id'],)).fetchall()
    file_list = []
    for f in files:
        file_list.append({
            "id": f["id"],
            "encrypted_filename": f["encrypted_original_filename"],
            "stored_filename": f["stored_filename"],
            "file_extension": f["file_extension"]
        })
    return jsonify({"status": "ok", "files": file_list})

# API endpoint for file download
@app.route('/api/download_file/<filename>', methods=['GET'])
def download_file(filename):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
