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

# Load .env file if present
load_dotenv()

UPLOAD_DIR = Path("uploads")
METADATA_FILE = Path("metadata.json")
SALT_FILE = Path("salt.bin")

UPLOAD_DIR.mkdir(exist_ok=True)
if not METADATA_FILE.exists():
    METADATA_FILE.write_text("{}")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(16))

# Master secret (password) must be provided in environment
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD")
if not MASTER_PASSWORD:
    raise RuntimeError("Set MASTER_PASSWORD in environment (see README.md)")

# Derive encryption key with PBKDF2
salt = SALT_FILE.read_bytes() if SALT_FILE.exists() else None
key_info = derive_key_from_password(MASTER_PASSWORD.encode(), salt=salt)
sym_key = key_info["key"]

# Save salt if it was just created
if not SALT_FILE.exists():
    SALT_FILE.write_bytes(key_info["salt"])


# --- Metadata helpers ---
def load_metadata():
    return json.loads(METADATA_FILE.read_text())

def save_metadata(m):
    METADATA_FILE.write_text(json.dumps(m, indent=2))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        flash("No file selected", "danger")
        return redirect(url_for("index"))

    orig_filename = secure_filename(f.filename)
    data = f.read()

    # Integrity hash
    sha256 = hashlib.sha256(data).hexdigest()

    # Encrypt
    nonce, ciphertext = encrypt_bytes(sym_key, data)

    # Save encrypted file
    stored_name = secrets.token_hex(12) + ".enc"
    out_path = UPLOAD_DIR / stored_name
    with out_path.open("wb") as fh:
        fh.write(nonce + ciphertext)

    # Save metadata
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
    meta = load_metadata()
    items = [{"stored_name": k, **v} for k, v in meta.items()]
    return render_template("list.html", files=items)


@app.route("/download/<stored_name>")
def download(stored_name):
    meta = load_metadata()
    if stored_name not in meta:
        flash("File not found", "danger")
        return redirect(url_for("list_files"))

    path = UPLOAD_DIR / stored_name
    if not path.exists():
        flash("Encrypted file missing on server", "danger")
        return redirect(url_for("list_files"))

    data = path.read_bytes()
    nonce, ciphertext = data[:12], data[12:]

    try:
        plaintext = decrypt_bytes(sym_key, nonce, ciphertext)
    except Exception:
        flash("Decryption failed: authentication error", "danger")
        return redirect(url_for("list_files"))

    # Check integrity
    expected = meta[stored_name]["sha256"]
    actual = hashlib.sha256(plaintext).hexdigest()
    if actual != expected:
        flash("Warning: integrity check failed", "warning")

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=meta[stored_name]["original_filename"],
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
