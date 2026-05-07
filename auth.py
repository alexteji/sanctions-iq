import sqlite3
import os
from datetime import datetime, timedelta
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, current_app, g
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

auth_bp = Blueprint("auth", __name__)
login_manager = LoginManager()

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

# ─── User model ──────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, id, email, name, role="analyst"):
        self.id = id
        self.email = email
        self.name = name
        self.role = role

    @staticmethod
    def get(user_id):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        con.close()
        if row:
            return User(row["id"], row["email"], row["name"], row["role"])
        return None

    @staticmethod
    def get_by_email(email):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM users WHERE lower(email)=?", (email.lower(),)).fetchone()
        con.close()
        return row

# ─── Login manager setup ─────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("auth.login", next=request.path))

# ─── Token helpers ───────────────────────────────────────────────────────────

def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

def _make_reset_token(email):
    return _serializer().dumps(email, salt="pw-reset")

def _verify_reset_token(token, max_age=3600):
    try:
        email = _serializer().loads(token, salt="pw-reset", max_age=max_age)
        return email
    except (SignatureExpired, BadSignature):
        return None

# ─── Email helper ─────────────────────────────────────────────────────────────

def _send_reset_email(to_email, reset_url):
    """Send password reset email via Resend. Falls back to console in dev."""
    import requests as _requests

    api_key = os.getenv("RESEND_API_KEY", "")
    from_addr = os.getenv("RESEND_FROM", "SanctionsIQ <noreply@sanctionsiq.app>")

    html_body = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:520px;margin:40px auto;background:#111520;border:1px solid #2a3050;border-radius:10px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:28px 32px">
        <div style="font-size:22px;font-weight:700;color:#fff">&#9878; SanctionsIQ</div>
        <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:4px">Password Reset Request</div>
      </div>
      <div style="padding:32px;color:#e2e8f0">
        <p style="font-size:15px;margin-bottom:20px">A password reset was requested for <strong>{to_email}</strong>.</p>
        <p style="font-size:13px;color:#94a3b8;margin-bottom:24px">Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
        <a href="{reset_url}" style="display:inline-block;background:#3b82f6;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">Reset My Password &rarr;</a>
        <p style="font-size:12px;color:#64748b;margin-top:24px">If you didn't request this, you can safely ignore this email.</p>
        <p style="font-size:12px;color:#64748b;margin-top:6px">Or copy: <code style="background:#1a1f2e;padding:2px 6px;border-radius:4px;font-size:11px">{reset_url}</code></p>
      </div>
    </div>
    """

    if api_key:
        try:
            resp = _requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "from": from_addr,
                    "to": [to_email],
                    "subject": "SanctionsIQ — Reset your password",
                    "html": html_body,
                },
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            current_app.logger.error(f"Resend error: {e}")
            return False
    else:
        # Dev mode — print link to terminal so it's usable without email config
        current_app.logger.warning(
            f"\n{'='*60}\n"
            f"  PASSWORD RESET LINK  (set RESEND_API_KEY for real email)\n"
            f"  Email : {to_email}\n"
            f"  URL   : {reset_url}\n"
            f"{'='*60}\n"
        )
        return "dev"

# ─── Routes ───────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        row = User.get_by_email(email)
        if row and check_password_hash(row["password_hash"], password):
            user = User(row["id"], row["email"], row["name"], row["role"])
            login_user(user, remember=remember)
            next_page = request.args.get("next") or url_for("index")
            # Protect open redirect
            if not next_page.startswith("/"):
                next_page = url_for("index")
            return redirect(next_page)
        error = "Invalid email or password."
    return render_template("login.html", error=error)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not name or not email or not password:
            error = "All fields are required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif User.get_by_email(email):
            error = "An account with that email already exists."
        else:
            con = sqlite3.connect(DB_PATH)
            con.execute(
                "INSERT INTO users(email, name, password_hash, role) VALUES(?,?,?,?)",
                (email, name, generate_password_hash(password, method="pbkdf2:sha256"), "analyst")
            )
            con.commit()
            row = User.get_by_email(email)
            user = User(row["id"], row["email"], row["name"], row["role"])
            login_user(user)
            return redirect(url_for("index"))
    return render_template("register.html", error=error)

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    sent = False
    dev_url = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        row = User.get_by_email(email)
        if row:
            token = _make_reset_token(email)
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            result = _send_reset_email(email, reset_url)
            if result == "dev":
                dev_url = reset_url
        # Always show success to prevent email enumeration
        sent = True
    return render_template("forgot_password.html", sent=sent, dev_url=dev_url)

@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = _verify_reset_token(token)
    if not email:
        return render_template("reset_password.html", expired=True, token=token)
    error = None
    success = False
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            con = sqlite3.connect(DB_PATH)
            con.execute(
                "UPDATE users SET password_hash=? WHERE lower(email)=?",
                (generate_password_hash(password, method="pbkdf2:sha256"), email)
            )
            con.commit()
            con.close()
            success = True
    return render_template("reset_password.html", email=email, token=token, error=error, success=success, expired=False)
