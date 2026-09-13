import os

from flask import Flask
from flask import request
from flask_wtf import CSRFProtect

from auth import auth_bp
from config import Config
from db import init_db
from vault import vault_bp
from url_sentinel import url_sentinel_bp

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
    app.register_blueprint(url_sentinel_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    return app


if __name__ == "__main__":
    app = create_app()
    # debug=True is only for local development — turn it off in production.
    app.run(debug=True)
