import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import PyPDF2

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'docx', 'xlsx', 'pptx', 'csv', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_encryption_key():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')

def encrypt_file_aes256(input_path, output_path, key):
    key_bytes = base64.urlsafe_b64decode(key)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(iv)
        while True:
            chunk = fin.read(4096)
            if not chunk:
                break
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())

def decrypt_file_aes256(input_path, output_path, key):
    key_bytes = base64.urlsafe_b64decode(key)
    with open(input_path, 'rb') as fin:
        iv = fin.read(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        with open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(4096)
                if not chunk:
                    break
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())

def get_secure_filename(filename):
    return secure_filename(filename)

def encrypt_file_fernet(input_path, output_path, key):
    f = Fernet(key)
    with open(input_path, 'rb') as fin:
        data = fin.read()
    encrypted = f.encrypt(data)
    with open(output_path, 'wb') as fout:
        fout.write(encrypted)

def decrypt_file_fernet(input_path, output_path, key):
    f = Fernet(key)
    with open(input_path, 'rb') as fin:
        data = fin.read()
    decrypted = f.decrypt(data)
    with open(output_path, 'wb') as fout:
        fout.write(decrypted)

def generate_fernet_key():
    return Fernet.generate_key().decode('utf-8')

def encrypt_file_chacha20(input_path, output_path, key):
    key_bytes = base64.urlsafe_b64decode(key)
    nonce = secrets.token_bytes(12)
    aead = ChaCha20Poly1305(key_bytes)
    with open(input_path, 'rb') as fin:
        data = fin.read()
    encrypted = aead.encrypt(nonce, data, None)
    with open(output_path, 'wb') as fout:
        fout.write(nonce + encrypted)

def decrypt_file_chacha20(input_path, output_path, key):
    key_bytes = base64.urlsafe_b64decode(key)
    with open(input_path, 'rb') as fin:
        nonce = fin.read(12)
        data = fin.read()
    aead = ChaCha20Poly1305(key_bytes)
    decrypted = aead.decrypt(nonce, data, None)
    with open(output_path, 'wb') as fout:
        fout.write(decrypted)

def generate_chacha20_key():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')

def pdf_password_protect(input_path, output_path, password):
    reader = PyPDF2.PdfReader(input_path)
    writer = PyPDF2.PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(password)
    with open(output_path, 'wb') as fout:
        writer.write(fout)
