from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import os
from functools import wraps
from pathlib import Path
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)

# SECRET KEY
app.secret_key = os.getenv("SECRET_KEY")

# DATABASE
DATABASE_DIR = Path(os.getenv("LOCALAPPDATA", app.root_path)) / "flask-notes-app"
DATABASE_PATH = DATABASE_DIR / "notes.db"

# MAIL CONFIGURATION
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "saiaaditya1343@gmail.com"
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)

# TOKEN SERIALIZER
serializer = URLSafeTimedSerializer(app.secret_key)


def get_connection():
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def get_db():
    return get_connection()


def init_db():
    with get_connection() as db:

        with open(
            Path(app.root_path) / "schema.sql",
            "r",
            encoding="utf-8"
        ) as schema_file:

            db.executescript(schema_file.read())


init_db()


def run_query(
    query,
    params=(),
    fetch_one=False,
    fetch_all=False,
    commit=False
):
    db = get_db()

    cursor = db.cursor()

    cursor.execute(query, params)

    result = None

    if fetch_one:
        result = cursor.fetchone()

    elif fetch_all:
        result = cursor.fetchall()

    if commit:
        db.commit()

    cursor.close()
    db.close()

    return result


def current_user_id():
    return session.get("user_id")


def note_or_404(note_id):

    note = run_query(
        """
        SELECT *
        FROM notes
        WHERE id = ?
        AND user_id = ?
        """,
        (note_id, current_user_id()),
        fetch_one=True
    )

    if not note:
        return None

    return note


def login_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if not current_user_id():
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


@app.route("/")
def home():

    if current_user_id():
        return redirect(url_for("viewall"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)

        try:

            run_query(
                """
                INSERT INTO users
                (username, email, password)
                VALUES (?, ?, ?)
                """,
                (username, email, hashed_pw),
                commit=True
            )

            flash(
                "Registration successful! Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash(
                "Username or email already exists.",
                "danger"
            )

    return render_template("register.html")


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

            return redirect(url_for("viewall"))

        flash(
            "Invalid username or password!",
            "danger"
        )

    return render_template("login.html")


# =========================
# FORGOT PASSWORD
# =========================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        user = run_query(
            """
            SELECT *
            FROM users
            WHERE lower(email) = ?
            """,
            (email,),
            fetch_one=True
        )

        if user:

            token = serializer.dumps(
                email,
                salt="password-reset-salt"
            )

            reset_link = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            msg = Message(
                "Password Reset Request",
                sender=app.config["MAIL_USERNAME"],
                recipients=[email]
            )

            msg.body = f"""
Hello,

Click the link below to reset your password:

{reset_link}

If you did not request this,
please ignore this email.
"""

            mail.send(msg)

        flash(
            "If the email exists, a reset link has been sent.",
            "info"
        )

        return redirect(url_for("login"))

    return redirect(url_for("forgot_password"))


# =========================
# RESET PASSWORD
# =========================
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    try:

        email = serializer.loads(
            token,
            salt="password-reset-salt",
            max_age=3600
        )

    except:

        flash(
            "Reset link is invalid or expired.",
            "danger"
        )

        return redirect(url_for("forget_password"))

    if request.method == "POST":

        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "warning"
            )

            return render_template("reset_password.html")

        if len(new_password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "warning"
            )

            return render_template("reset_password.html")

        hashed_password = generate_password_hash(
            new_password
        )

        run_query(
            """
            UPDATE users
            SET password = ?
            WHERE lower(email) = ?
            """,
            (hashed_password, email),
            commit=True
        )

        flash(
            "Password updated successfully.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Logged out successfully.",
        "info"
    )

    return redirect(url_for("login"))


@app.route("/addnote", methods=["GET", "POST"])
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
            (title, content, current_user_id()),
            commit=True
        )

        flash(
            "Note added!",
            "success"
        )

        return redirect(url_for("viewall"))

    return render_template("addnote.html")


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
        notes=notes,
        query=""
    )


@app.route("/viewnotes/<int:id>")
@login_required
def viewnote(id):

    note = note_or_404(id)

    if not note:
        return "Note not found", 404

    return render_template(
        "viewnote.html",
        note=note
    )


@app.route("/updatenote/<int:id>", methods=["GET", "POST"])
@login_required
def updatenote(id):

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        run_query(
            """
            UPDATE notes
            SET title = ?, content = ?
            WHERE id = ?
            AND user_id = ?
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

        return redirect(url_for("viewall"))

    note = note_or_404(id)

    if not note:
        return "Note not found", 404

    return render_template(
        "updatenote.html",
        note=note
    )


@app.route("/deletenote/<int:id>")
@login_required
def deletenote(id):

    run_query(
        """
        DELETE FROM notes
        WHERE id = ?
        AND user_id = ?
        """,
        (id, current_user_id()),
        commit=True
    )

    flash(
        "Note deleted.",
        "warning"
    )

    return redirect(url_for("viewall"))


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():

    query = request.values.get(
        "q",
        ""
    ).strip()

    if not query:
        return redirect(url_for("viewall"))

    if not re.match(
        r"^[a-zA-Z0-9 ]+$",
        query
    ):

        flash(
            "Search can only use letters, numbers, and spaces.",
            "warning"
        )

        return redirect(url_for("viewall"))

    notes = run_query(
        """
        SELECT *
        FROM notes
        WHERE user_id = ?
        AND title LIKE ?
        ORDER BY created_at DESC
        """,
        (
            current_user_id(),
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
    app.run(debug=True)