import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)


class Config:
    # Used by Flask to sign session cookies. Keep secret, never commit it.
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # Base64-encoded 32-byte (256-bit) key used for AES-256-GCM file encryption.
    MASTER_KEY = os.environ.get("MASTER_KEY", "")
    KEY_ID = os.environ.get("KEY_ID", "master-v1")

    DATABASE = os.path.join(DATA_DIR, "vault.db")
    UPLOAD_FOLDER = os.path.join(DATA_DIR, "encrypted_files")
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
