import os
import sqlite3
import time
from functools import wraps
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, url_for, session, request, render_template, \
    send_file, abort, flash, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# --- Config ---
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data.db"
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
UPLOAD_FOLDER = BASE_DIR / UPLOAD_FOLDER
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "sakshamranjan7@gmail.com")
SIGNED_TOKEN_EXPIRY = int(os.getenv("SIGNED_TOKEN_EXPIRY", "300"))  # seconds

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY
app.config.update({
    'UPLOAD_FOLDER': str(UPLOAD_FOLDER),
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax'
})

# --- OAuth (Google) ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    authorize_params={'access_type': 'offline', 'prompt': 'select_account'},
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    client_kwargs={'scope': 'openid email profile'}
)

# --- Login manager ---
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Tiny user model (stored in session only)
class User(UserMixin):
    def __init__(self, id, email, name, is_owner=False):
        self.id = id
        self.email = email
        self.name = name
        self.is_owner = is_owner

@login_manager.user_loader
def load_user(user_id):
    # We store user in session; keep it simple:
    data = session.get("user")
    if data and data.get("id") == user_id:
        return User(id=data["id"], email=data["email"], name=data["name"], is_owner=data.get("is_owner", False))
    return None

# --- Signed token generator for protected streaming links ---
ts = URLSafeTimedSerializer(SECRET_KEY)

def generate_signed_token(content_id):
    return ts.dumps({"id": content_id})

def validate_signed_token(token, max_age=SIGNED_TOKEN_EXPIRY):
    try:
        data = ts.loads(token, max_age=max_age)
        return data.get("id")
    except SignatureExpired:
        return None
    except BadSignature:
        return None

# --- Database helpers (SQLite simple) ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS contents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            title TEXT,
            description TEXT,
            mimetype TEXT,
            uploaded_by TEXT,
            created_at INTEGER
        )
        """)
        conn.commit()

def insert_content(filename, title, description, mimetype, uploaded_by):
    ts_now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO contents (filename, title, description, mimetype, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (filename, title, description, mimetype, uploaded_by, ts_now))
        conn.commit()
        return cur.lastrowid

def get_contents():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, filename, title, description, mimetype, uploaded_by, created_at FROM contents ORDER BY created_at DESC")
        rows = cur.fetchall()
        return [dict(id=r[0], filename=r[1], title=r[2], description=r[3], mimetype=r[4], uploaded_by=r[5], created_at=r[6]) for r in rows]

def get_content_by_id(content_id):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, filename, title, description, mimetype, uploaded_by, created_at FROM contents WHERE id=?", (content_id,))
        r = cur.fetchone()
        if not r: return None
        return dict(id=r[0], filename=r[1], title=r[2], description=r[3], mimetype=r[4], uploaded_by=r[5], created_at=r[6])

# --- Decorators ---
def owner_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_owner", False):
            abort(403)
        return view(*args, **kwargs)
    return wrapped

# --- Routes ---
@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    contents = get_contents()
    # For each content, produce a signed token for streaming endpoint (short lived)
    for c in contents:
        c['signed_token'] = generate_signed_token(c['id'])
    resp = make_response(render_template("index.html", user=current_user, contents=contents))
    # Security headers (CSP reduces embedding/copying risk)
    resp.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none';"
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp

@app.route("/login")
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    token = google.authorize_access_token()
    if not token:
        return "Failed to authenticate", 400
    resp = google.get('userinfo')
    profile = resp.json()
    user_email = profile.get("email")
    user_id = profile.get("id")
    user_name = profile.get("name") or profile.get("email")
    is_owner = (user_email.lower() == OWNER_EMAIL.lower())
    user = User(id=user_id, email=user_email, name=user_name, is_owner=is_owner)
    # store user in session
    session["user"] = {"id": user.id, "email": user.email, "name": user.name, "is_owner": is_owner}
    login_user(user)
    return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
@owner_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        title = request.form.get("title", "")
        description = request.form.get("description", "")
        if not f:
            flash("No file provided.", "danger")
            return redirect(url_for("upload"))
        # simple filename sanitization
        fname = f.filename
        # ensure uniqueness
        ts_now = int(time.time())
        filename = f"{ts_now}_{fname}"
        dest = UPLOAD_FOLDER / filename
        f.save(dest)
        mimetype = f.mimetype or "application/octet-stream"
        cid = insert_content(filename, title, description, mimetype, current_user.email)
        flash("Uploaded successfully.", "success")
        return redirect(url_for("index"))
    return render_template("upload.html", user=current_user)

@app.route("/watch/<int:content_id>")
@login_required
def watch(content_id):
    content = get_content_by_id(content_id)
    if not content:
        abort(404)
    # verify token param
    token = request.args.get("token")
    if not token or validate_signed_token(token) != str(content_id):
        flash("Invalid or expired viewing link. Please access via site.", "danger")
        return redirect(url_for("index"))
    # Render a protected player page
    resp = make_response(render_template("watch.html", content=content))
    resp.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' data:; frame-ancestors 'none';"
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp

@app.route("/stream/<int:content_id>")
def stream(content_id):
    """
    Streaming endpoint that checks a signed token provided via header 'X-Stream-Token'
    or query arg 'token'. It returns the file with headers that discourage direct download.
    """
    token = request.args.get("token") or request.headers.get("X-Stream-Token")
    if not token:
        abort(403)
    valid = validate_signed_token(token)
    if not valid or int(valid) != content_id:
        abort(403)
    content = get_content_by_id(content_id)
    if not content:
        abort(404)
    filepath = UPLOAD_FOLDER / content['filename']
    if not filepath.exists():
        abort(404)
    # Serve file as inline stream and prevent caching
    response = make_response(send_file(str(filepath), mimetype=content['mimetype'], conditional=True))
    # Important headers to discourage saving/caching
    response.headers['Content-Disposition'] = 'inline'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    # Disallow being embedded by other sites
    response.headers['X-Frame-Options'] = 'DENY'
    return response

# Admin: delete content
@app.route("/admin/delete/<int:content_id>", methods=["POST"])
@login_required
@owner_required
def delete_content(content_id):
    content = get_content_by_id(content_id)
    if not content:
        abort(404)
    # remove file and db record
    filepath = UPLOAD_FOLDER / content['filename']
    try:
        if filepath.exists():
            filepath.unlink()
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM contents WHERE id=?", (content_id,))
            conn.commit()
    except Exception as e:
        flash(f"Error deleting: {e}", "danger")
        return redirect(url_for("index"))
    flash("Deleted.", "success")
    return redirect(url_for("index"))

# --- Initialize DB if needed ---
init_db()

# --- Static simple health check ---
@app.route("/health")
def health():
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
