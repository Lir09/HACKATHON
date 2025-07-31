from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, bcrypt, os
from functools import wraps
import random

app = Flask(__name__)
app.secret_key = 'supersecret!'
DB_NAME = 'users.db'

# -----------------------------
# DB 초기화 (회원테이블 생성)
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
            email TEXT PRIMARY KEY,
            name TEXT,
            phone TEXT,
            address TEXT,
            password_hash TEXT
        )''')
        conn.commit()
        conn.close()
init_db()

# -----------------------------
# 로그인 필수 데코레이터
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# -----------------------------
# 메인페이지 (로그인 필요)
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('user'))

# -----------------------------
# 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return render_template('signup.html', error="이미 등록된 이메일입니다.")
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", (email, name, phone, address, pw_hash))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

# -----------------------------
# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember')
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[4]):
            session['user'] = user[1]
            session['email'] = user[0]
            if remember == "on":
                session.permanent = True
                app.permanent_session_lifetime = 60 * 60 * 24 * 7  # 일주일 유지
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="이메일 또는 비밀번호가 잘못되었습니다.")
    return render_template('login.html')

# -----------------------------
# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -----------------------------
@app.route('/find_password', methods=['GET', 'POST'])
def find_password():
    if request.method == 'POST':
        step = int(request.form.get('step', 1))
        email = request.form.get('email')
        code = request.form.get('code')
        new_pw = request.form.get('new_password')
        if step == 1:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            conn.close()
            if not user:
                return render_template('find_password.html', error="등록되지 않은 이메일입니다.", email=email, step=1)
            session['pwreset_email'] = email
            session['pwreset_code'] = str(random.randint(100000, 999999))
            return render_template('find_password.html', step=2, email=email, code=session['pwreset_code'])
        elif step == 2:
            if code != session.get('pwreset_code'):
                return render_template('find_password.html', step=2, email=email, error="인증번호가 다릅니다.", code=session.get('pwreset_code'))
            pw_hash = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
            conn.commit()
            conn.close()
            session.pop('pwreset_email', None)
            session.pop('pwreset_code', None)
            return render_template('find_password.html', step=3, success="비밀번호 변경 완료!")
    # ★ 반드시 return!
    return render_template('find_password.html', step=1)


# -----------------------------
# 로그인 상태 확인 (AJAX 지원)
@app.route('/api/user')
def api_user():
    if 'user' in session:
        return jsonify({'login': True, 'username': session['user']})
    return jsonify({'login': False})

# -----------------------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

