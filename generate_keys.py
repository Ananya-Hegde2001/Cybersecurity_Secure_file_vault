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
