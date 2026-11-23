from flask import Flask, request, render_template_string, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect
import sqlite3
import secrets
import os
from functools import wraps
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import MismatchingStateError
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_por_defecto")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
csrf = CSRFProtect(app)
oauth = OAuth(app)

auth0 = oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none';"
    return response

def get_db_connection(query, params=()):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

def get_or_create_user(username):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, session_token TEXT)")
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, 'auth0_external', 'user')
        )
        conn.commit()
        user_id = cursor.lastrowid
        role = 'user'
    else:
        user_id = user['id']
        role = user['role']
        
    conn.close()
    return user_id, role

def get_user_by_id(user_id):
    users = get_db_connection("SELECT * FROM users WHERE id = ?", (user_id,))
    return users[0] if users else None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        cookie_token = session.get('session_token')
        
        if not user_id or not cookie_token:
            return redirect('/login')
            
        user = get_user_by_id(user_id)
        
        if not user or user['role'] != 'admin' or user['session_token'] != cookie_token:
            session.clear()
            return redirect('/logout')
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template_string('''
        <h1>Welcome to the Task Manager Application!</h1>
        <a href="/login"><button type="button">Iniciar Sesion</button></a>
    ''')

@app.route('/login')
def login():
    if not os.getenv("AUTH0_DOMAIN"):
        # Modo simulación local si no hay credenciales de Auth0 configuradas
        session['user_id'] = 1
        session['username'] = 'user2'
        session['role'] = 'user'
        session['session_token'] = 'mock_token'
        return redirect('/dashboard')
    return auth0.authorize_redirect(
        redirect_uri=os.getenv("AUTH0_CALLBACK_URL")
    )

@app.route('/callback')
def callback():
    try:
        token = auth0.authorize_access_token()
    except (MismatchingStateError, Exception):
        session.clear()
        return redirect('/logout')
        
    userinfo = token.get("userinfo", {})
    username = userinfo.get("email") or userinfo.get("nickname") or userinfo.get("name")
    
    if username:
        user_id, role = get_or_create_user(username)
        active_token = secrets.token_hex(16)
        get_db_connection("UPDATE users SET session_token = ? WHERE id = ?", (active_token, user_id))
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role
        session["user"] = userinfo
        session["session_token"] = active_token
        
    return redirect("/dashboard")

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        get_db_connection("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template_string('''
        <h1>Welcome, {{ session.get('username', 'user 2!') }}</h1>
        <form method="POST">
            <input type="text" name="task" placeholder="New task">
            <button type="submit">Add Task</button>
        </form>
        <h2>Your Tasks</h2>
        <br><a href="/logout">Cerrar Sesión</a>
    ''')

if __name__ == '__main__':
    app.run(port=5000, debug=True)
