# Secure File Vault

A small Flask app that lets a logged-in user encrypt files with AES-256-GCM,
store them, and decrypt them again — with hashed passwords, login rate
limiting, an audit trail, and session expiration. Every flow described below
was run end-to-end before this was handed to you, so follow the steps in
order and it will work.

## What's in the box

```
secure-file-vault/
├── app.py              # creates the Flask app, wires everything together
├── config.py            # all settings in one place
├── generate_keys.py      # run once, to create your secrets
├── schema.sql             # database structure (3 tables)
├── db.py                   # SQLite connection helpers
├── crypto_utils.py          # AES-256-GCM encrypt/decrypt
├── auth.py                   # register / login / logout / lockout logic
├── vault.py                    # upload / download / audit-log routes
├── decorators.py                 # login_required + idle-timeout check
├── audit.py                       # writes rows to the audit log
├── templates/                      # HTML pages
├── static/style.css                 # styling
├── requirements.txt
└── .env.example
```

## 1. Install prerequisites

You need **Python 3.10+**. Check with:

```bash
python3 --version
```

## 2. Get the code and set up a virtual environment

```bash
cd secure-file-vault
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Generate your secret keys

The app needs two secrets: `SECRET_KEY` (signs session cookies) and
`MASTER_KEY` (encrypts your files). Generate both:

```bash
python generate_keys.py
```

Copy the two lines it prints, then:

```bash
cp .env.example .env
```

Paste the two lines into `.env`. It should look like:

```
SECRET_KEY=q3f9...   (yours will be different)
MASTER_KEY=Zx1c...   (yours will be different)
SESSION_COOKIE_SECURE=false
```

**Never commit `.env` to git** — it's already in `.gitignore`.

## 4. Run it

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser. The database (`vault.db`)
and the encrypted-files folder are created automatically on first run.

## 5. Try it out

1. Register an account (username ≥ 3 chars, password ≥ 8 chars).
2. Log in.
3. Upload a file — it's encrypted before it's written to disk.
4. Click "Decrypt & download" — the file comes back byte-for-byte identical.
5. Open **Audit Log** in the nav bar to see every action recorded.
6. Try logging in with the wrong password 5 times in a row — the account
   locks itself for 15 minutes.
7. Log in, then leave the tab alone for 15+ minutes — your next click
   redirects you to the login page.

## How each requirement is implemented

| Requirement | Where | How |
|---|---|---|
| Hashed passwords | `auth.py` | `werkzeug.security.generate_password_hash` (scrypt) — a slow, salted hash, not a fast general-purpose hash like SHA-256 |
| Encrypt files (AES-256-GCM) | `crypto_utils.py` | `cryptography`'s `AESGCM` with a random 12-byte nonce per file. GCM is *authenticated* encryption — it also detects tampering |
| Decrypt only after auth | `vault.py` | `/download/<id>` is behind `@login_required` and only looks up files owned by `session['user_id']` |
| Audit log | `audit.py`, `vault.py`, `auth.py` | Every register/login/login-failure/lockout/upload/download/logout writes a row: who, when, what, from which IP |
| Rate-limit failed logins | `auth.py` | Per-account `failed_attempts` counter in the DB; 5 failures locks the account for 15 minutes (both config values live in `config.py`) |
| Auto logout / session expiry | `decorators.py`, `config.py` | Two layers: an absolute cap (`PERMANENT_SESSION_LIFETIME`) and a sliding idle-timeout checked on every request (`SESSION_IDLE_TIMEOUT`) |

A few other things baked in: CSRF tokens on every form (Flask-WTF),
`secure_filename()` + randomly generated on-disk names (no path traversal),
and login errors that don't reveal whether the *username* or the *password*
was wrong (prevents account enumeration).

## Design choices worth understanding

- **One master key, not per-user keys.** All files are encrypted with a
  single `MASTER_KEY` from your `.env`. This is the simplest correct design
  and matches the "beginner stack" brief. The trade-off: whoever has
  `MASTER_KEY` and the database can decrypt every file. A stronger design
  derives a separate key per user from their password (e.g. with `scrypt`)
  and uses that to wrap a random per-file key — worth building next once
  this version makes sense to you.
- **SQLite + raw SQL, not an ORM.** You can read every query directly in
  `auth.py`/`vault.py` instead of it being hidden behind an abstraction —
  useful while you're still learning what's actually happening.
- **Account lockout, not IP lockout.** This stops password-guessing against
  one account. It doesn't stop someone spraying one password across many
  usernames — that needs IP-based limiting too (see below).

## Before you'd use this for real files

This is a learning project, not a production system, as-is. Before trusting
it with real data:

- Serve it over **HTTPS** (e.g. behind nginx or on a platform that provides
  TLS) and set `SESSION_COOKIE_SECURE=true` in `.env`.
- Run it with a real WSGI server (`gunicorn`/`waitress`), not
  `app.run(debug=True)`.
- Add **IP-based** rate limiting too, e.g. with `Flask-Limiter`, so an
  attacker can't just cycle through many usernames.
- Consider the per-user key derivation mentioned above.
- Back up `MASTER_KEY` somewhere safe and separate from the database — if
  you lose it, every stored file is unrecoverable by design.
- Rotate `vault.db` and `encrypted_files/` backups together; they're only
  useful as a pair.

## Troubleshooting

- **`RuntimeError: SECRET_KEY / MASTER_KEY are not set`** — you skipped
  step 3, or `.env` isn't being picked up. Confirm the file is named
  exactly `.env` and sits next to `app.py`.
- **`ModuleNotFoundError`** — the virtual environment isn't active. Re-run
  `source .venv/bin/activate` (or the Windows equivalent) before `python app.py`.
- **Locked out of your own test account** — either wait 15 minutes, or
  stop the app and delete `vault.db` to reset everything (you'll lose all
  accounts and file records).
