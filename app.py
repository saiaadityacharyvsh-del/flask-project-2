from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash,
    url_for,
    jsonify
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

from functools import wraps
from pathlib import Path

import sqlite3
import re
import os


app = Flask(__name__)

# =====================================
# SECRET KEY
# =====================================

app.secret_key = os.getenv(
    "SECRET_KEY",
    "super-secret-key"
)

# =====================================
# DATABASE
# =====================================

DATABASE_DIR = Path(app.instance_path)
DATABASE_PATH = DATABASE_DIR / "notes.db"

# =====================================
# MAIL CONFIG
# =====================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER") or app.config["MAIL_USERNAME"]
mail = Mail(app) if app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"] else None

# =====================================
# TOKEN SERIALIZER
# =====================================

serializer = URLSafeTimedSerializer(
    app.secret_key
)

# =====================================
# DATABASE CONNECTION
# =====================================

def get_connection():

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE_PATH
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


def run_query(
    query,
    params=(),
    fetch_one=False,
    fetch_all=False,
    commit=False
):

    with get_connection() as conn:

        cursor = conn.cursor()

        cursor.execute(query, params)

        result = None

        if fetch_one:
            result = cursor.fetchone()

        elif fetch_all:
            result = cursor.fetchall()

        if commit:
            conn.commit()

        cursor.close()

        return result


# =====================================
# INITIALIZE DATABASE
# =====================================

def init_db():
    conn = None
    try:
        conn = get_connection()
        with open(
            Path(app.root_path) / "schema.sql",
            encoding="utf-8"
        ) as f:
            conn.executescript(f.read())
    finally:
        if conn is not None:
            conn.close()


init_db()

# =====================================
# HELPERS
# =====================================

def current_user_id():
    return session.get("user_id")


def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if not current_user_id():
            flash(
                "Please login first.",
                "warning"
            )

            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def note_or_404(note_id):

    note = run_query(
        """
        SELECT *
        FROM notes
        WHERE id = ?
        AND user_id = ?
        """,
        (
            note_id,
            current_user_id()
        ),
        fetch_one=True
    )
    return note


# =====================================
# HOME
# =====================================

@app.route("/")
def home():

    if current_user_id():
        return redirect(url_for("viewall"))

    return redirect(url_for("login"))


# =====================================
# REGISTER
# =====================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        # Validation

        if not re.match(
            r"^[a-zA-Z0-9_]{3,20}$",
            username
        ):

            flash(
                "Invalid username.",
                "danger"
            )

            return render_template("register.html")

        if len(password) < 6:

            flash(
                "Password too short.",
                "danger"
            )

            return render_template("register.html")

        if not re.match(
            r"[^@]+@[^@]+\.[^@]+",
            email
        ):

            flash(
                "Invalid email.",
                "danger"
            )

            return render_template("register.html")

        hashed_pw = generate_password_hash(password)

        try:

            run_query(
                """
                INSERT INTO users
                (username, email, password)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    hashed_pw
                ),
                commit=True
            )

            flash(
                "Registration successful!",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash(
                "Username or email already exists.",
                "danger"
            )

    return render_template("register.html")


# =====================================
# LOGIN
# =====================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        user = run_query(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,),
            fetch_one=True
        )

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash(
                "Welcome back!",
                "success"
            )

            return redirect(url_for("viewall"))

        flash(
            "Invalid credentials.",
            "danger"
        )

    return render_template("login.html")


# =====================================
# FORGOT PASSWORD
# =====================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)

def forgot_password():

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        user = run_query(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,),
            fetch_one=True
        )

        if user:

            token = serializer.dumps(
                email,
                salt="password-reset"
            )

            reset_link = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            if mail:
                msg = Message(
                    "Password Reset",
                    sender=app.config["MAIL_USERNAME"],
                    recipients=[email]
                )

                msg.body = f"""
Reset your password:
 
{reset_link}
"""
                mail.send(msg)
            else:
                print(f"Reset link (mail disabled): {reset_link}")

        flash(
            "If the email exists, a reset link was sent.",
            "info"
        )

        return redirect(url_for("login"))

    return render_template(
        "forget_password.html"
    )


# =====================================
# RESET PASSWORD
# =====================================

@app.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)

def reset_password(token):

    try:

        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=3600
        )

    except Exception:

        flash(
            "Invalid or expired link.",
            "danger"
        )

        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        password = request.form["new_password"]
        confirm = request.form["confirm_password"]

        if password != confirm:

            flash(
                "Passwords do not match.",
                "warning"
            )

            return render_template(
                "reset_password.html"
            )

        hashed = generate_password_hash(
            password
        )

        run_query(
            """
            UPDATE users
            SET password = ?
            WHERE lower(email) = ?
            """,
            (hashed, email),
            commit=True
        )

        flash(
            "Password updated.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "reset_password.html"
    )


# =====================================
# LOGOUT
# =====================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Logged out successfully.",
        "info"
    )

    return redirect(url_for("login"))


# =====================================
# ADD NOTE
# =====================================

@app.route(
    "/addnote",
    methods=["GET", "POST"]
)

@login_required
def addnote():

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        run_query(
            """
            INSERT INTO notes
            (title, content, user_id)
            VALUES (?, ?, ?)
            """,
            (
                title,
                content,
                current_user_id()
            ),
            commit=True
        )

        flash(
            "Note added!",
            "success"
        )

        return redirect(url_for("viewall"))

    return render_template("addnote.html")


# =====================================
# UPDATE NOTE
# =====================================

@app.route(
    "/updatenote/<int:id>",
    methods=["GET", "POST"]
)

@login_required
def updatenote(id):

    note = note_or_404(id)

    if not note:

        flash(
            "Note not found.",
            "danger"
        )

        return redirect(url_for("viewall"))

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        run_query(
            """
            UPDATE notes
            SET title = ?, content = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                title,
                content,
                id,
                current_user_id()
            ),
            commit=True
        )

        flash(
            "Note updated!",
            "success"
        )

        return redirect(url_for("viewnote", id=id))

    return render_template(
        "updatenote.html",
        note=note
    )


# =====================================
# VIEW NOTES
# =====================================

@app.route("/viewall")
@login_required
def viewall():

    notes = run_query(
        """
        SELECT *
        FROM notes
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (current_user_id(),),
        fetch_all=True
    )

    return render_template(
        "viewall.html",
        notes=notes
    )
# =====================================
# VIEW SINGLE NOTE
# =====================================

@app.route("/viewnote/<int:id>")
@login_required
def viewnote(id):

    note = note_or_404(id)

    if not note:

        flash(
            "Note not found.",
            "danger"
        )

        return redirect(url_for("viewall"))

    return render_template(
        "viewnote.html",
        note=note
    )


# =====================================
# DELETE NOTE (GET ONLY)
# =====================================

@app.route(
    "/deletenote/<int:id>",
    methods=["GET"]
)

@login_required
def deletenote(id):

    run_query(
        """
        DELETE FROM notes
        WHERE id = ?
        AND user_id = ?
        """,
        (
            id,
            current_user_id()
        ),
        commit=True
    )

    flash(
        "Note deleted!",
        "success"
    )

    return redirect(url_for("viewall"))


# =====================================
# SEARCH
# =====================================

@app.route("/search")
@login_required
def search():

    query = request.args.get(
        "q",
        ""
    ).strip()

    if not query:
        return redirect(url_for("viewall"))

    notes = run_query(
        """
        SELECT *
        FROM notes
        WHERE user_id = ?
        AND (
            title LIKE ?
            OR content LIKE ?
        )
        ORDER BY created_at DESC
        """,
        (
            current_user_id(),
            f"%{query}%",
            f"%{query}%"
        ),
        fetch_all=True
    )

    return render_template(
        "viewall.html",
        notes=notes,
        query=query
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)