import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Parameters
KDF_ITERATIONS = 200_000
KEY_LENGTH = 32   # 256-bit AES
SALT_LENGTH = 16
NONCE_LENGTH = 12  # Recommended for AES-GCM


def derive_key_from_password(password: bytes, salt: bytes | None = None):
    """Derive a 32-byte AES key from password. If salt is None, generate new salt."""
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return {"key": key, "salt": salt}


def encrypt_bytes(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
