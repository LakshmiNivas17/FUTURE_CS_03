
import os
import json
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from io import BytesIO

from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from crypto import derive_key_from_password, encrypt_bytes, decrypt_bytes

# Load environment variables from .env file
load_dotenv()

# Define paths for uploads, metadata, and salt file
UPLOAD_DIR = Path("uploads")
METADATA_FILE = Path("metadata.json")
SALT_FILE = Path("salt.bin")

# Create uploads directory if not already present
UPLOAD_DIR.mkdir(exist_ok=True)

# Create an empty metadata.json file if it does not exist
if not METADATA_FILE.exists():
    METADATA_FILE.write_text("{}")

# Initialize Flask app
app = Flask(__name__)

# Flask secret key for session management
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(16))

# Get master password from environment (used for encryption key derivation)
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD")
if not MASTER_PASSWORD:
    raise RuntimeError("Set MASTER_PASSWORD in environment (see README.md)")

# Derive encryption key using PBKDF2-HMAC with SHA256
salt = SALT_FILE.read_bytes() if SALT_FILE.exists() else None
key_info = derive_key_from_password(MASTER_PASSWORD.encode(), salt=salt)
sym_key = key_info["key"]

# If salt file did not exist, save the newly generated salt
if not SALT_FILE.exists():
    SALT_FILE.write_bytes(key_info["salt"])


# -------------------- Metadata helpers --------------------
def load_metadata():
    """Load metadata.json into a Python dictionary."""
    return json.loads(METADATA_FILE.read_text())

def save_metadata(m):
    """Save updated metadata dictionary back into metadata.json."""
    METADATA_FILE.write_text(json.dumps(m, indent=2))


# -------------------- Routes --------------------

@app.route("/")
def index():
    """Render homepage (upload form and navigation)."""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    """Handle file uploads, encrypt them, and store metadata."""
    f = request.files.get("file")
    if not f:
        flash("No file selected", "danger")
        return redirect(url_for("index"))

    # Sanitize original filename
    orig_filename = secure_filename(f.filename)

    # Read raw file data
    data = f.read()

    # Generate SHA256 hash for integrity verification
    sha256 = hashlib.sha256(data).hexdigest()

    # Encrypt file contents using AES-GCM
    nonce, ciphertext = encrypt_bytes(sym_key, data)

    # Create random name for stored encrypted file
    stored_name = secrets.token_hex(12) + ".enc"
    out_path = UPLOAD_DIR / stored_name

    # Save encrypted file (nonce + ciphertext)
    with out_path.open("wb") as fh:
        fh.write(nonce + ciphertext)

    # Store file metadata
    meta = load_metadata()
    meta[stored_name] = {
        "original_filename": orig_filename,
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "sha256": sha256,
        "size_bytes": len(data),
    }
    save_metadata(meta)

    flash(f"Uploaded and encrypted: {orig_filename}", "success")
    return redirect(url_for("index"))


@app.route("/files")
def list_files():
    """List all uploaded encrypted files along with metadata."""
    meta = load_metadata()
    items = [{"stored_name": k, **v} for k, v in meta.items()]
    return render_template("list.html", files=items)


@app.route("/download/<stored_name>")
def download(stored_name):
    """Decrypt and allow downloading of a selected file."""
    meta = load_metadata()
    if stored_name not in meta:
        flash("File not found", "danger")
        return redirect(url_for("list_files"))

    # Locate encrypted file
    path = UPLOAD_DIR / stored_name
    if not path.exists():
        flash("Encrypted file missing on server", "danger")
        return redirect(url_for("list_files"))

    # Read file (first 12 bytes = nonce, rest = ciphertext)
    data = path.read_bytes()
    nonce, ciphertext = data[:12], data[12:]

    try:
        # Attempt decryption
        plaintext = decrypt_bytes(sym_key, nonce, ciphertext)
    except Exception:
        flash("Decryption failed: authentication error", "danger")
        return redirect(url_for("list_files"))

    # Verify file integrity with stored SHA256
    expected = meta[stored_name]["sha256"]
    actual = hashlib.sha256(plaintext).hexdigest()
    if actual != expected:
        flash("Warning: integrity check failed", "warning")

    # Send decrypted file to user
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=meta[stored_name]["original_filename"],
    )


# Run the Flask app
if __name__ == "__main__":
    # Debug mode enabled for development (disable in production)
    app.run(host="0.0.0.0", port=5000, debug=True)
