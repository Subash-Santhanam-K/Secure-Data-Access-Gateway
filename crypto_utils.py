import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

KEY_FILE = "aes.key"
ENCRYPTED_KEY_FILE = "aes_encrypted.key"
KEYS_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "public_key.pem")

def generate_rsa_keys():
    """Generates RSA key pair and saves them to the keys directory."""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
        
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_rsa_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def load_rsa_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_aes_key(aes_key):
    """Encrypts AES key using RSA public key."""
    public_key = load_rsa_public_key()
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def get_aes_key():
    """
    Retrieves the AES key. 
    1. If aes_encrypted.key exists, decrypts it using RSA private key.
    2. Fallback (Migration support): If aes.key exists, use it.
    3. Else, generate new (should not happen in prod flow ideally without RSA setup).
    """
    if os.path.exists(ENCRYPTED_KEY_FILE):
        # Hybrid Encryption Flow
        with open(ENCRYPTED_KEY_FILE, "rb") as f:
            encrypted_key = f.read()
            
        private_key = load_rsa_private_key()
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
        
    elif os.path.exists(KEY_FILE):
        # Legacy/Setup Flow
        with open(KEY_FILE, "rb") as f:
             return f.read()
    else:
        # Generate new AES key (and ideally trigger RSA encryption if keys exist, 
        # but for simplicity we just return raw key and let migration script handle storage)
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

def get_cipher():
    """
    Returns a Fernet cipher instance using the loaded key.
    """
    key = get_aes_key()
    return Fernet(key)

import hashlib

def hash_data(data: bytes):
    return hashlib.sha256(data).digest()

def sign_hash(hash_bytes):
    private_key = load_rsa_private_key()
    signature = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(hash_bytes, signature):
    public_key = load_rsa_public_key()
    try:
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def encrypt_text(text: str) -> str:
    cipher = get_cipher()
    encrypted = cipher.encrypt(text.encode())
    return encrypted.hex()

def decrypt_text(enc_hex: str) -> str:
    cipher = get_cipher()
    decrypted = cipher.decrypt(bytes.fromhex(enc_hex))
    return decrypted.decode()
