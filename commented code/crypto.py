
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Parameters for encryption and key derivation
KDF_ITERATIONS = 200_000   # Number of PBKDF2 iterations (for security)
KEY_LENGTH = 32            # AES-256 key length (32 bytes)
SALT_LENGTH = 16           # Random salt size (16 bytes)
NONCE_LENGTH = 12          # Recommended nonce size for AES-GCM


def derive_key_from_password(password: bytes, salt: bytes | None = None):
    """
    Derive a secure AES key from a password using PBKDF2-HMAC-SHA256.
    - password: user-supplied master password (in bytes).
    - salt: random salt (if None, a new one is generated).
    Returns: dict with {"key": derived_key, "salt": used_salt}.
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)  # Generate random salt if not provided

    # PBKDF2 Key Derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )

    # Derive AES key
    key = kdf.derive(password)
    return {"key": key, "salt": salt}


def encrypt_bytes(key: bytes, plaintext: bytes):
    """
    Encrypt plaintext using AES-GCM.
    - key: AES key (32 bytes).
    - plaintext: raw file data.
    Returns: (nonce, ciphertext).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)  # Random nonce for each encryption
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes):
    """
    Decrypt ciphertext using AES-GCM.
    - key: AES key (32 bytes).
    - nonce: unique random value used during encryption.
    - ciphertext: encrypted file data.
    Returns: plaintext (decrypted data).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
