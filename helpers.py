import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from flask import redirect, render_template, session
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    
    return decorated_function


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive a symmetric vault key from the user's password and stored salt"""
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


def encrypt_text(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext and return encrypted bytes"""
    f = Fernet(key)
    return f.encrypt(plaintext.encode())


def decrypt_text(ciphertext: bytes, key: bytes) -> str:
    """Decrypt encrypted bytes and return plaintet string"""
    f = Fernet(key)
    return f.decrypt(ciphertext).decode()
