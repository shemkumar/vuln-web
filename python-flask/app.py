# INTENTIONALLY VULNERABLE: for SAST/DevSecOps scanner validation only.
import hashlib
import os
import pickle
import sqlite3
import subprocess
import yaml
import requests
from flask import Flask, request, render_template_string, jsonify, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'flask-insecure-secret'  # A02/A07 hardcoded secret
app.config['DEBUG'] = True  # A05 debug mode
API_KEY = 'sk_test_fake_1234567890'  # fake secret for scanner validation

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    digest = hashlib.sha1(password.encode()).hexdigest()  # A02 weak hash
    sql = "SELECT id, role FROM users WHERE username='%s' AND password='%s'" % (username, digest)  # A03 SQLi
    print('auth attempt', username, password, sql)  # A09 sensitive logging
    conn = sqlite3.connect('app.db')
    rows = conn.execute(sql).fetchall()
    if not rows:
        return 'bad login', 403
    session['user_id'] = rows[0][0]
    session['role'] = rows[0][1]
    return jsonify({'ok': True})

@app.route('/profile/<user_id>')
def profile(user_id):
    # A01 IDOR: no ownership check against session user.
    conn = sqlite3.connect('app.db')
    rows = conn.execute('SELECT id, email, ssn FROM users WHERE id=' + user_id).fetchall()
    return jsonify(rows)

@app.route('/admin/export')
def admin_export():
    # A01 no admin authorization; A03 command injection.
    table = request.args.get('table', 'users')
    output = subprocess.check_output('sqlite3 app.db "select * from ' + table + '"', shell=True)
    return output

@app.route('/template')
def template():
    # A03 server-side template injection.
    name = request.args.get('name', 'guest')
    return render_template_string('Hello ' + name)

@app.route('/load-yaml', methods=['POST'])
def load_yaml():
    # A08 unsafe YAML deserialization.
    obj = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({'loaded_type': str(type(obj))})

@app.route('/pickle', methods=['POST'])
def load_pickle():
    # A08 unsafe pickle deserialization.
    obj = pickle.loads(request.data)
    return jsonify({'object': str(obj)})

@app.route('/fetch')
def fetch():
    # A10 SSRF and disabled TLS verification.
    url = request.args.get('url')
    r = requests.get(url, verify=False, timeout=3)
    return r.text

@app.route('/download')
def download():
    # A01 path traversal / arbitrary file read.
    file_name = request.args.get('file')
    with open(os.path.join('/var/app/files', file_name), 'r') as f:
        return f.read()

@app.route('/reset')
def reset():
    # A04 predictable token derived from user-controlled email.
    email = request.args.get('email', '')
    return hashlib.md5((email + 'static-salt').encode()).hexdigest()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
