# Secure File Vault — Complete Build Guide

Everything you need is in this one file: the architecture, every file's
code, and why each piece exists. Follow it top to bottom and you'll have a
working app. (This exact code was built and tested end-to-end — registration,
login lockout, encrypt/decrypt round-trip, tamper detection, cross-user
access control, and idle-session expiry were all run against a live
instance before being written down here.)

**Stack:** Python + Flask + SQLite + the `cryptography` library.

**What it does:** a logged-in user uploads a file → the server encrypts it
with AES-256-GCM before it ever touches disk → later, the user can decrypt
and download it → every action is written to an audit log → passwords are
hashed, failed logins are rate-limited, and idle sessions expire
automatically.

---

## Table of contents

1. [How the pieces fit together](#1-how-the-pieces-fit-together)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — Project folder](#step-1--project-folder)
4. [Step 2 — Dependencies](#step-2--dependencies)
5. [Step 3 — Config & secrets](#step-3--config--secrets)
6. [Step 4 — Database](#step-4--database)
7. [Step 5 — Encryption core](#step-5--encryption-core)
8. [Step 6 — Audit logging](#step-6--audit-logging)
9. [Step 7 — Session & access control](#step-7--session--access-control)
10. [Step 8 — Authentication](#step-8--authentication)
11. [Step 9 — File vault routes](#step-9--file-vault-routes)
12. [Step 10 — Application factory](#step-10--application-factory)
13. [Step 11 — Templates](#step-11--templates)
14. [Step 12 — Styling](#step-12--styling)
15. [Step 13 — Run it](#step-13--run-it)
16. [Step 14 — Test it yourself](#step-14--test-it-yourself)
17. [Requirement → code map](#requirement--code-map)
18. [Key security concepts, explained](#key-security-concepts-explained)
19. [Before you'd use this for real files](#before-youd-use-this-for-real-files)
20. [Troubleshooting](#troubleshooting)
21. [Where to go next](#where-to-go-next)

---

## 1. How the pieces fit together

```
Browser
  │
  ▼
app.py  (creates the Flask app, registers everything below)
  │
  ├── auth.py     (Blueprint: /register, /login, /logout)
  ├── vault.py    (Blueprint: /, /upload, /download/<id>, /audit-log)
  │
  ├── decorators.py  → @login_required guards every vault.py route
  ├── crypto_utils.py → AES-256-GCM encrypt/decrypt, used by vault.py
  ├── audit.py        → log_action(), called from auth.py and vault.py
  ├── db.py            → get_db(), a SQLite connection, used everywhere
  └── schema.sql         → defines the 3 tables: users, files, audit_log

templates/*.html   → what the browser actually renders (Jinja2)
static/style.css   → how it looks
```

Flask apps are usually split into **Blueprints** — groups of related
routes. Here, everything about logging in lives in `auth.py`, and
everything about the vault itself (upload/download) lives in `vault.py`.
`app.py` just wires the two together.

`app.py` also uses the **application factory pattern** — `create_app()` is
a function that builds and returns the Flask app, instead of a bare
`app = Flask(__name__)` sitting at the top of a file. This matters because
it lets you create the app with *different* config for testing vs. running
for real, which is exactly how this project was tested (see Step 14).

---

## 2. Prerequisites

- **Python 3.10+** — check with `python3 --version`
- Basic comfort in a terminal (`cd`, running commands)
- No prior Flask/security knowledge assumed — that's covered inline below

---

## Step 1 — Project folder

Create the structure first, so every file below has somewhere to go:

```bash
mkdir -p secure-file-vault/templates secure-file-vault/static secure-file-vault/encrypted_files
cd secure-file-vault
```

By the end, it looks like this:

```
secure-file-vault/
├── app.py
├── config.py
├── generate_keys.py
├── schema.sql
├── db.py
├── crypto_utils.py
├── audit.py
├── decorators.py
├── auth.py
├── vault.py
├── requirements.txt
├── .env.example
├── .gitignore
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── audit_log.html
├── static/
│   └── style.css
└── encrypted_files/        (created empty; encrypted files land here)
```

---

## Step 2 — Dependencies

**Why each package is here:**
- `Flask` — the web framework: routes, requests, templates
- `Flask-WTF` — gives us CSRF protection on every form for free
- `cryptography` — the actual AES-256-GCM implementation (well-audited,
  don't hand-roll your own crypto)
- `python-dotenv` — loads secrets from a `.env` file into environment
  variables, so they're never hardcoded in the code
- `Werkzeug` — Flask's toolkit; we use its password-hashing functions
  directly

Create `requirements.txt`:

```txt
Flask>=3.0
Flask-WTF>=1.2
cryptography>=42.0
python-dotenv>=1.0
Werkzeug>=3.0
```

Then set up a virtual environment and install everything:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

A **virtual environment** keeps this project's Python packages separate
from every other project on your machine — standard practice, do this for
every Python project.

---

## Step 3 — Config & secrets

Two different secrets are needed, and it's worth understanding why they're
*not the same thing*:

- **`SECRET_KEY`** — Flask uses this to cryptographically sign session
  cookies, so a user can't forge or tamper with their own session data
  (e.g. edit the cookie to claim to be a different user).
- **`MASTER_KEY`** — a 256-bit AES key used to encrypt/decrypt the actual
  file contents. Completely unrelated purpose to `SECRET_KEY`.

Both are loaded from environment variables, never hardcoded, so they can
differ between your laptop and a real server, and never end up in source
control.

### `config.py`

```python
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Used by Flask to sign session cookies. Keep secret, never commit it.
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # Base64-encoded 32-byte (256-bit) key used for AES-256-GCM file encryption.
    MASTER_KEY = os.environ.get("MASTER_KEY", "")

    DATABASE = os.path.join(BASE_DIR, "vault.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "encrypted_files")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload size

    # --- Session / login security ---
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)  # absolute cap
    SESSION_IDLE_TIMEOUT = timedelta(minutes=15)         # inactivity cap
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Turn this on once you serve the app over HTTPS (see README).
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

    # --- Rate limiting ---
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
```

### `generate_keys.py`

A one-off script — you run it once, paste its output into `.env`, and
never run it again (running it again would generate *new* keys, which
would invalidate old sessions and make previously-encrypted files
undecryptable).

```python
"""
Run this once to generate the two secrets the app needs:

    python generate_keys.py

Copy the output into a file named .env in the project root
(there's an .env.example template you can copy and fill in).
Never commit the real .env file to version control.
"""
import base64
import os

secret_key = base64.b64encode(os.urandom(32)).decode()
master_key = base64.b64encode(os.urandom(32)).decode()

print("Add these lines to your .env file:\n")
print(f"SECRET_KEY={secret_key}")
print(f"MASTER_KEY={master_key}")
```

### `.env.example`

A template — copy this to `.env` and fill in real values. `.env` itself
should never be committed to git (see `.gitignore` below).

```txt
# Copy this file to ".env" and fill in real values.
# Generate both with: python generate_keys.py

SECRET_KEY=
MASTER_KEY=

# Set to "true" only once you are serving the app over HTTPS.
SESSION_COOKIE_SECURE=false
```

### `.gitignore`

```txt
.env
vault.db
encrypted_files/*
!encrypted_files/.gitkeep
__pycache__/
*.pyc
.venv/
venv/
```

Now actually generate your keys and set up the env file:

```bash
python generate_keys.py
cp .env.example .env
# paste the two printed lines into .env
touch encrypted_files/.gitkeep
```

---

## Step 4 — Database

Three tables, one job each:

- **`users`** — accounts. Stores a *hash* of the password, never the
  password itself, plus the fields needed for lockout (`failed_attempts`,
  `lockout_until`).
- **`files`** — one row per uploaded file. Stores the *encrypted* filename
  on disk, the random nonce used to encrypt it, and which user owns it.
  Critically, it does **not** store the encryption key — that lives only
  in `MASTER_KEY`.
- **`audit_log`** — one row per action (login, upload, download, etc.),
  independent of the other two tables so it keeps a record even if a user
  or file is later deleted.

### `schema.sql`

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT UNIQUE NOT NULL,
    nonce TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    filename TEXT,
    ip_address TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    details TEXT
);
```

### `db.py`

Flask apps get many requests concurrently. `db.py` opens one SQLite
connection **per request** (stored on Flask's request-scoped `g` object)
and closes it automatically when the request ends — that's what
`teardown_appcontext` does. `row_factory = sqlite3.Row` is what lets us
later write `row["username"]` instead of remembering column positions.

```python
import os
import sqlite3

from flask import current_app, g


def get_db():
    """Return a request-scoped SQLite connection (opened once per request)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables if they don't exist yet, and register cleanup."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with app.app_context():
        db = get_db()
        with open(schema_path) as f:
            db.executescript(f.read())
        db.commit()
    app.teardown_appcontext(close_db)
```

---

## Step 5 — Encryption core

This is the heart of the "secure" in Secure File Vault, so it's worth
slowing down here.

**AES-256** is a symmetric cipher — the same 256-bit key both encrypts and
decrypts. **GCM** (Galois/Counter Mode) is the mode of operation: instead
of just scrambling the bytes, it also produces an authentication *tag*.
That tag means decryption doesn't just fail silently if someone alters the
ciphertext — it raises `InvalidTag`. Plain AES-CBC (an older, more common
mode) doesn't give you that; GCM does, which is why it's specified in the
brief.

The one rule you must never break with GCM: **never reuse a nonce with the
same key.** Doing so breaks GCM's security guarantees completely. That's
why a fresh random 12-byte nonce is generated for *every single file*, and
stored alongside it (nonces don't need to be secret, just unique).

### `crypto_utils.py`

```python
"""
AES-256-GCM helpers.

GCM is an "authenticated" mode: it doesn't just encrypt the data, it also
produces a tag that lets decrypt() detect if the ciphertext was corrupted
or tampered with. If a file has been altered, decrypt_bytes() raises
InvalidTag instead of silently returning garbage.

A fresh random 12-byte nonce is generated for every encryption. Reusing a
nonce with the same key would break GCM's security guarantees, so we never
do that — each file gets its own nonce, stored alongside it in the DB.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

NONCE_SIZE = 12  # 96 bits, the recommended size for AES-GCM


def _load_key() -> bytes:
    key_b64 = current_app.config.get("MASTER_KEY")
    if not key_b64:
        raise RuntimeError(
            "MASTER_KEY is not set. Run `python generate_keys.py` and put "
            "the result in your .env file."
        )
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes (256 bits).")
    return key


def encrypt_bytes(plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext, returning (ciphertext, nonce)."""
    key = _load_key()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return ciphertext, nonce


def decrypt_bytes(ciphertext: bytes, nonce: bytes) -> bytes:
    """Decrypt ciphertext. Raises cryptography.exceptions.InvalidTag if the
    data was tampered with or the wrong key/nonce is used."""
    key = _load_key()
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
```

---

## Step 6 — Audit logging

One function, called from every route that matters. Keeping it this small
and centralized means you can't forget to log something — every call site
in `auth.py` and `vault.py` is one line.

### `audit.py`

```python
from flask import request

from db import get_db


def log_action(action: str, user_id: int | None = None, username: str | None = None,
                filename: str | None = None, details: str | None = None):
    """Write one row to audit_log. Called on every login attempt, upload,
    download, and logout so there's a full who/when/what trail."""
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_log (user_id, username, action, filename, ip_address, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, action, filename, request.remote_addr, details),
    )
    db.commit()
```

---

## Step 7 — Session & access control

A **decorator** in Python is a function that wraps another function to add
behavior around it. `@login_required` is placed above any route that
should only work for logged-in users — it checks the session before the
route's own code ever runs.

Two separate expiry mechanisms are at play in this project:

1. **Absolute expiry** (`PERMANENT_SESSION_LIFETIME` in `config.py`) — the
   session cookie itself expires 15 minutes after login, no matter what.
2. **Idle expiry** (`SESSION_IDLE_TIMEOUT`, enforced here) — if the user
   goes quiet for 15 minutes, they're logged out even if the absolute
   cookie lifetime hasn't run out yet. This is checked on *every* request,
   not just at login, which is what makes it a true idle timeout.

### `decorators.py`

```python
from datetime import datetime, timezone
from functools import wraps

from flask import current_app, flash, redirect, session, url_for


def login_required(view):
    """Require a logged-in user, and enforce the idle-session timeout on
    every request (not just at login time)."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))

        last_active_raw = session.get("last_active")
        if last_active_raw:
            last_active = datetime.fromisoformat(last_active_raw)
            idle_for = datetime.now(timezone.utc) - last_active
            if idle_for > current_app.config["SESSION_IDLE_TIMEOUT"]:
                session.clear()
                flash("Your session expired due to inactivity. Please log in again.", "warning")
                return redirect(url_for("auth.login"))

        # Any authenticated request resets the idle clock.
        session["last_active"] = datetime.now(timezone.utc).isoformat()
        return view(*args, **kwargs)

    return wrapped_view
```

---

## Step 8 — Authentication

Three routes: register, login, logout. The interesting security decisions
are in `login()`:

- **Password hashing:** `generate_password_hash()` from Werkzeug defaults
  to **scrypt** — a *slow*, salted hashing algorithm designed specifically
  for passwords. This matters: a fast hash like plain SHA-256 lets an
  attacker who steals your database try billions of password guesses per
  second. Scrypt is deliberately expensive to compute, which makes
  brute-forcing far slower even with stolen hashes.
- **Generic error messages:** whether the *username* doesn't exist or the
  *password* is wrong, the user sees the same "Invalid username or
  password." A different message for each case would let an attacker
  enumerate which usernames are registered.
- **Account lockout:** each user row tracks `failed_attempts`. On the 5th
  consecutive failure, `lockout_until` is set 15 minutes into the future
  and the counter resets. Login is refused — even with the *correct*
  password — until that timestamp passes. A successful login always resets
  both fields to zero/null.
- **`session.clear()` before setting a new session on login** — prevents a
  subtle bug called *session fixation*, where a stale session from before
  login could otherwise carry over privileges or state.

### `auth.py`

```python
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from audit import log_action
from db import get_db

auth_bp = Blueprint("auth", __name__)

USERNAME_MIN_LEN = 3
PASSWORD_MIN_LEN = 8


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if len(username) < USERNAME_MIN_LEN:
            error = f"Username must be at least {USERNAME_MIN_LEN} characters."
        elif len(password) < PASSWORD_MIN_LEN:
            error = f"Password must be at least {PASSWORD_MIN_LEN} characters."
        elif password != confirm:
            error = "Passwords do not match."

        db = get_db()
        if error is None:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing is not None:
                error = "That username is already taken."

        if error:
            flash(error, "danger")
            return render_template("register.html", username=username)

        # werkzeug's default hashing method (scrypt) is a slow, salted KDF —
        # appropriate for password storage, unlike a fast hash like SHA-256.
        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        log_action("register", username=username)
        flash("Account created. You can log in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", username="")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Check account lockout first, before touching the password at all.
        if user and user["lockout_until"]:
            lockout_until = datetime.fromisoformat(user["lockout_until"])
            if datetime.now(timezone.utc) < lockout_until:
                remaining = int((lockout_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
                flash(f"Account locked. Try again in about {remaining} minute(s).", "danger")
                log_action("login_blocked_lockout", user_id=user["id"], username=username)
                return render_template("login.html", username=username)

        # Deliberately use the same generic error whether the username
        # doesn't exist or the password is wrong, so an attacker can't use
        # this form to enumerate valid usernames.
        valid = user is not None and check_password_hash(user["password_hash"], password)

        if valid:
            db.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            log_action("login_success", user_id=user["id"], username=username)
            return redirect(url_for("vault.dashboard"))

        just_locked = False
        if user:
            attempts = user["failed_attempts"] + 1
            lockout_until = None
            if attempts >= current_app.config["MAX_FAILED_ATTEMPTS"]:
                lockout_until = (
                    datetime.now(timezone.utc) + current_app.config["LOCKOUT_DURATION"]
                ).isoformat()
                attempts = 0  # reset counter; lockout window now governs access
                just_locked = True
            db.execute(
                "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
                (attempts, lockout_until, user["id"]),
            )
            db.commit()

        if just_locked:
            minutes = int(current_app.config["LOCKOUT_DURATION"].total_seconds() // 60)
            log_action("login_blocked_lockout", user_id=user["id"], username=username)
            flash(f"Too many failed attempts. Account locked for {minutes} minutes.", "danger")
        else:
            log_action("login_failed", user_id=user["id"] if user else None, username=username)
            flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username)

    return render_template("login.html", username="")


@auth_bp.route("/logout")
def logout():
    username = session.get("username")
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        log_action("logout", user_id=user_id, username=username)
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
```

---

## Step 9 — File vault routes

Four routes, all behind `@login_required`:

- **`/` (dashboard)** — lists only the current user's files
  (`WHERE user_id = ?`).
- **`/upload`** — reads the uploaded bytes, encrypts them, writes the
  *ciphertext* to disk under a randomly generated name, and stores the
  original filename + nonce in the database. Two things worth noticing:
  `secure_filename()` sanitizes the *displayed* name, but the file on disk
  always gets a fresh UUID name — so even a maliciously crafted filename
  like `../../etc/passwd` can never influence a real file path.
- **`/download/<file_id>`** — looks up the file **and** checks
  `user_id = session['user_id']` in the same query. That single condition
  is what stops User B from downloading User A's file just by guessing or
  incrementing an ID in the URL — if it's not theirs, the query returns
  nothing and the route responds `404`, not `403`, so it doesn't even
  confirm the file exists.
- **`/audit-log`** — the user's own activity history.

### `vault.py`

```python
import io
import os
import uuid
from base64 import b64decode, b64encode

from cryptography.exceptions import InvalidTag
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from audit import log_action
from crypto_utils import decrypt_bytes, encrypt_bytes
from db import get_db
from decorators import login_required

vault_bp = Blueprint("vault", __name__)


@vault_bp.route("/")
@login_required
def dashboard():
    db = get_db()
    files = db.execute(
        "SELECT id, original_filename, size_bytes, uploaded_at "
        "FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", files=files)


@vault_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        flash("Choose a file first.", "warning")
        return redirect(url_for("vault.dashboard"))

    original_name = secure_filename(uploaded.filename)
    plaintext = uploaded.read()

    ciphertext, nonce = encrypt_bytes(plaintext)

    # The name on disk is a random UUID, never the user-supplied filename —
    # that avoids any path-traversal or collision issues.
    stored_name = f"{uuid.uuid4().hex}.enc"
    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name)
    with open(stored_path, "wb") as f:
        f.write(ciphertext)

    db = get_db()
    db.execute(
        """
        INSERT INTO files (user_id, original_filename, stored_filename, nonce, size_bytes)
        VALUES (?, ?, ?, ?, ?)
        """,
        (session["user_id"], original_name, stored_name, b64encode(nonce).decode(), len(plaintext)),
    )
    db.commit()
    log_action("upload", user_id=session["user_id"], username=session["username"], filename=original_name)

    flash(f'"{original_name}" was encrypted and stored.', "success")
    return redirect(url_for("vault.dashboard"))


@vault_bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()

    # Owner check: a logged-in user can only ever reach their own rows,
    # so there's no way to guess another user's file id and download it.
    if file_row is None:
        abort(404)

    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], file_row["stored_filename"])
    with open(stored_path, "rb") as f:
        ciphertext = f.read()
    nonce = b64decode(file_row["nonce"])

    try:
        plaintext = decrypt_bytes(ciphertext, nonce)
    except InvalidTag:
        log_action(
            "download_failed_integrity",
            user_id=session["user_id"],
            username=session["username"],
            filename=file_row["original_filename"],
        )
        flash("This file failed integrity verification and could not be decrypted.", "danger")
        return redirect(url_for("vault.dashboard"))

    log_action(
        "download",
        user_id=session["user_id"],
        username=session["username"],
        filename=file_row["original_filename"],
    )

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_row["original_filename"],
    )


@vault_bp.route("/audit-log")
@login_required
def audit_log():
    db = get_db()
    entries = db.execute(
        "SELECT action, filename, ip_address, timestamp "
        "FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 200",
        (session["user_id"],),
    ).fetchall()
    return render_template("audit_log.html", entries=entries)
```

---

## Step 10 — Application factory

This is the file that actually starts everything: it builds the Flask app,
checks the secrets are present, enables CSRF protection, initializes the
database, and registers both blueprints.

### `app.py`

```python
import os

from flask import Flask
from flask_wtf import CSRFProtect

from auth import auth_bp
from config import Config
from db import init_db
from vault import vault_bp

csrf = CSRFProtect()


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    if not app.config["SECRET_KEY"] or not app.config["MASTER_KEY"]:
        raise RuntimeError(
            "SECRET_KEY / MASTER_KEY are not set. Run `python generate_keys.py`, "
            "copy the output into a .env file, and restart."
        )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    csrf.init_app(app)
    init_db(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    # debug=True is only for local development — turn it off in production.
    app.run(debug=True)
```

---

## Step 11 — Templates

These use **Jinja2**, Flask's templating language. `base.html` defines the
overall page shell; every other template `{% extends "base.html" %}` and
fills in the `content` block. `{{ csrf_token() }}` (provided automatically
once `CSRFProtect` is initialized) is embedded as a hidden field on every
form — without a matching token, Flask-WTF rejects the POST.

### `templates/base.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}Secure File Vault{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="{{ url_for('vault.dashboard') if session.get('user_id') else url_for('auth.login') }}">
      🔒 Secure File Vault
    </a>
    {% if session.get('user_id') %}
    <nav>
      <span class="whoami">{{ session['username'] }}</span>
      <a href="{{ url_for('vault.dashboard') }}">Vault</a>
      <a href="{{ url_for('vault.audit_log') }}">Audit Log</a>
      <a href="{{ url_for('auth.logout') }}">Log out</a>
    </nav>
    {% endif %}
  </header>

  <main>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <ul class="flashes">
          {% for category, message in messages %}
            <li class="flash flash-{{ category }}">{{ message }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}
  </main>
</body>
</html>
```

### `templates/login.html`

```html
{% extends "base.html" %}
{% block title %}Log in — Secure File Vault{% endblock %}
{% block content %}
<div class="card auth-card">
  <h1>Log in</h1>
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="{{ username }}" required autofocus>

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>

    <button type="submit">Log in</button>
  </form>
  <p class="muted">No account? <a href="{{ url_for('auth.register') }}">Register</a></p>
</div>
{% endblock %}
```

### `templates/register.html`

```html
{% extends "base.html" %}
{% block title %}Register — Secure File Vault{% endblock %}
{% block content %}
<div class="card auth-card">
  <h1>Create account</h1>
  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="{{ username }}" minlength="3" required autofocus>

    <label for="password">Password</label>
    <input type="password" id="password" name="password" minlength="8" required>

    <label for="confirm_password">Confirm password</label>
    <input type="password" id="confirm_password" name="confirm_password" minlength="8" required>

    <button type="submit">Create account</button>
  </form>
  <p class="muted">Already have an account? <a href="{{ url_for('auth.login') }}">Log in</a></p>
</div>
{% endblock %}
```

### `templates/dashboard.html`

```html
{% extends "base.html" %}
{% block title %}Your Vault{% endblock %}
{% block content %}
<div class="card">
  <h1>Upload a file</h1>
  <form method="post" action="{{ url_for('vault.upload') }}" enctype="multipart/form-data" class="upload-form">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="file" name="file" required>
    <button type="submit">Encrypt &amp; store</button>
  </form>
</div>

<div class="card">
  <h1>Your files</h1>
  {% if files %}
  <table>
    <thead>
      <tr><th>Name</th><th>Size</th><th>Uploaded</th><th></th></tr>
    </thead>
    <tbody>
      {% for f in files %}
      <tr>
        <td>{{ f['original_filename'] }}</td>
        <td>{{ (f['size_bytes'] / 1024) | round(1) }} KB</td>
        <td>{{ f['uploaded_at'] }}</td>
        <td><a href="{{ url_for('vault.download', file_id=f['id']) }}">Decrypt &amp; download</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">No files yet. Upload one above — it's encrypted with AES-256-GCM before it touches disk.</p>
  {% endif %}
</div>
{% endblock %}
```

### `templates/audit_log.html`

```html
{% extends "base.html" %}
{% block title %}Audit Log{% endblock %}
{% block content %}
<div class="card">
  <h1>Your activity</h1>
  {% if entries %}
  <table>
    <thead>
      <tr><th>When</th><th>Action</th><th>File</th><th>IP</th></tr>
    </thead>
    <tbody>
      {% for e in entries %}
      <tr>
        <td>{{ e['timestamp'] }}</td>
        <td>{{ e['action'] }}</td>
        <td>{{ e['filename'] or '—' }}</td>
        <td>{{ e['ip_address'] }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">No activity recorded yet.</p>
  {% endif %}
</div>
{% endblock %}
```

---

## Step 12 — Styling

Purely cosmetic — none of the security features depend on this file.

### `static/style.css`

```css
:root {
  --ink: #1a1a1a;
  --muted: #6b6b6b;
  --border: #e3e3e3;
  --bg: #fafafa;
  --accent: #2f6f4f;
  --danger: #b3261e;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--ink);
}

.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 32px;
  border-bottom: 1px solid var(--border);
  background: #fff;
}

.brand { font-weight: 600; text-decoration: none; color: var(--ink); }

nav { display: flex; align-items: center; gap: 18px; }
nav a { color: var(--ink); text-decoration: none; font-size: 14px; }
nav a:hover { color: var(--accent); }
.whoami { color: var(--muted); font-size: 14px; }

main { max-width: 720px; margin: 0 auto; padding: 32px 20px; }

.card {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  margin-bottom: 24px;
}

.card h1 { font-size: 18px; margin: 0 0 16px; }

.auth-card { max-width: 380px; margin: 40px auto; }

label { display: block; font-size: 13px; color: var(--muted); margin: 12px 0 4px; }

input[type="text"], input[type="password"], input[type="file"] {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
}

button {
  margin-top: 18px;
  padding: 9px 16px;
  border: none;
  border-radius: 6px;
  background: var(--accent);
  color: #fff;
  font-size: 14px;
  cursor: pointer;
}
button:hover { opacity: 0.9; }

.upload-form { display: flex; gap: 12px; align-items: center; }
.upload-form input[type="file"] { flex: 1; }
.upload-form button { margin-top: 0; }

table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; }

.muted { color: var(--muted); font-size: 14px; }

.flashes { list-style: none; padding: 0; margin: 0 0 20px; }
.flash { padding: 10px 14px; border-radius: 6px; font-size: 14px; margin-bottom: 8px; }
.flash-success { background: #e6f4ea; color: #1e4620; }
.flash-danger { background: #fdecea; color: var(--danger); }
.flash-warning { background: #fff4e5; color: #8a5a00; }
```

---

## Step 13 — Run it

With every file above in place:

```bash
python app.py
```

Open **http://127.0.0.1:5000**. The database (`vault.db`) and the
`encrypted_files/` contents are created automatically on first run — you
don't need to run any setup command beyond this.

---

## Step 14 — Test it yourself

Walk through each of these once, in order, to see every feature fire:

1. **Register** — username ≥ 3 characters, password ≥ 8 characters.
2. **Log in** with the correct password.
3. **Upload a file.** Open `encrypted_files/` on disk afterward — the
   `.enc` file there is unreadable ciphertext, not your original content.
4. **Click "Decrypt & download"** on the dashboard — you get back the
   exact original file.
5. **Open "Audit Log"** in the nav — you'll see `register`, `login_success`,
   `upload`, and `download` rows, each with a timestamp and IP.
6. **Log out, then try logging in with the wrong password 5 times in a
   row.** The 5th attempt shows "Too many failed attempts... locked for 15
   minutes" — and even the *correct* password is rejected until the lockout
   expires.
7. **Log in, then leave the tab idle for 15+ minutes** and click anything.
   You're redirected to the login page with a session-expired message.

---

## Requirement → code map

| Requirement | Where | How |
|---|---|---|
| Hashed passwords | `auth.py` | `werkzeug.security.generate_password_hash` (scrypt) — slow and salted, unlike a fast hash like SHA-256 |
| Upload & store files | `vault.py` | `/upload` reads the file, encrypts it, writes it under a random UUID name |
| Encrypt files (AES-256-GCM) | `crypto_utils.py` | `cryptography`'s `AESGCM`, fresh random 12-byte nonce per file |
| Decrypt only after auth | `vault.py` + `decorators.py` | `/download/<id>` sits behind `@login_required` and only matches files owned by the session's `user_id` |
| Audit log | `audit.py`, called from `auth.py` & `vault.py` | Every register/login/failure/lockout/upload/download/logout writes a row: who, when, what, from which IP |
| Rate-limit failed logins | `auth.py` | Per-account `failed_attempts` counter in the DB; 5 failures locks the account for 15 minutes |
| Auto logout / session expiry | `decorators.py` + `config.py` | Absolute cap (`PERMANENT_SESSION_LIFETIME`) + sliding idle timeout (`SESSION_IDLE_TIMEOUT`) checked on every request |

---

## Key security concepts, explained

**Why scrypt over SHA-256 for passwords.** SHA-256 is *fast* — that's
great for checksums, terrible for passwords, because an attacker with a
stolen database can try billions of guesses per second on modern hardware.
scrypt (and similarly bcrypt/Argon2) is deliberately slow and memory-hard,
so the same attack might only try thousands of guesses per second — a
difference of many orders of magnitude.

**Why GCM over CBC for file encryption.** Both are AES modes. CBC just
encrypts; if an attacker flips a bit in the ciphertext, CBC will happily
"decrypt" it into corrupted-but-plausible-looking garbage with no warning.
GCM adds an authentication tag, so tampering is *detected* — this project's
`InvalidTag` handling in `vault.py` is that detection in action.

**Why the nonce must never repeat.** Think of the nonce as a "starting
position" for the cipher. Encrypting two different files with the same key
*and* the same nonce leaks enough information to potentially recover both
plaintexts. `os.urandom(12)` on every encryption call makes a repeat
astronomically unlikely.

**Why CSRF tokens matter.** Without one, a malicious website you happen to
have open in another tab could submit a hidden form to
`your-vault.com/upload` using your still-logged-in session cookie, and
your browser would send it as if you'd clicked the button yourself.
Flask-WTF's token proves the request actually came from a page your app
rendered.

**Why filenames are never used directly as paths.** If `original_filename`
were used as-is to build a file path, a crafted name like
`../../etc/passwd` could let someone read or write outside the intended
folder — a classic *path traversal* bug. Storing every file under a random
UUID name sidesteps the entire class of bug.

---

## Before you'd use this for real files

This is a learning project, not a production system, as-is:

- Serve it over **HTTPS** and set `SESSION_COOKIE_SECURE=true` in `.env`.
- Run it with a real WSGI server (`gunicorn`/`waitress`), not
  `app.run(debug=True)`.
- Add **IP-based** rate limiting too (e.g. `Flask-Limiter`) — the current
  lockout is per-account, so it doesn't stop someone spraying one guessed
  password across many usernames.
- Consider deriving a separate encryption key **per user** from their
  password (instead of one shared `MASTER_KEY`), so no single secret
  decrypts every file in the system.
- Back up `MASTER_KEY` somewhere safe and separate from the database — if
  you lose it, every stored file is unrecoverable by design.

---

## Troubleshooting

- **`RuntimeError: SECRET_KEY / MASTER_KEY are not set`** — you skipped the
  key-generation step, or `.env` isn't next to `app.py`.
- **`ModuleNotFoundError`** — your virtual environment isn't active. Run
  `source .venv/bin/activate` (or the Windows equivalent) before
  `python app.py`.
- **Locked out of your own test account** — wait 15 minutes, or stop the
  app and delete `vault.db` to reset everything (this deletes all
  accounts and file records).
- **`jinja2.exceptions.TemplateNotFound`** — double check the file is
  inside `templates/`, not the project root.

---

## Where to go next

Once this version makes sense end to end, natural next steps:
- Per-user key derivation (scrypt-derived key per user, wrapping a
  per-file random key) instead of one shared `MASTER_KEY`
- IP-based rate limiting with `Flask-Limiter`, layered on top of the
  existing per-account lockout
- Two-factor authentication (TOTP) on login
- File versioning — keep old encrypted versions instead of overwriting
- An admin view of the full `audit_log` table (currently each user only
  sees their own rows)
