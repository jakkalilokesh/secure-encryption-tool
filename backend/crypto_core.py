import os, hashlib
from enum import Enum
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESSIV
from cryptography.hazmat.primitives.asymmetric import ed25519

CHUNK_SIZE = 1024 * 1024
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 10 * 1024 * 1024 * 1024
MAX_FILES = 100

class AEADAlgorithm(str, Enum):
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_256_SIV = "aes-256-siv"

def derive_password_key(password: str, salt: bytes) -> bytes:
    """Derive key from password using Scrypt"""
    return Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    ).derive(password.encode())

def hkdf(source: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF key derivation"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(source)

def deterministic_nonce(data: bytes) -> bytes:
    """Deterministic nonce generation for AES-SIV"""
    return hashlib.sha256(data).digest()[:12]

def encrypt_chunk(algo: AEADAlgorithm, key: bytes, chunk: bytes, nonce: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Encrypt a single chunk"""
    if algo == AEADAlgorithm.AES_256_SIV:
        if len(key) < 64:
             raise ValueError("AES-256-SIV requires a 64-byte key")
        cipher = AESSIV(key) 
        ciphertext = cipher.encrypt(chunk, [])
        return b"", ciphertext
    
    if nonce is None:
        nonce = os.urandom(12)
    
    if algo == AEADAlgorithm.AES_256_GCM:
        cipher = AESGCM(key[:32])
    elif algo == AEADAlgorithm.CHACHA20_POLY1305:
        cipher = ChaCha20Poly1305(key[:32])
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
    
    ciphertext = cipher.encrypt(nonce, chunk, None)
    return nonce, ciphertext

def decrypt_chunk(algo: AEADAlgorithm, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a single chunk"""
    if algo == AEADAlgorithm.AES_256_SIV:
        if len(key) < 64:
             raise ValueError("AES-256-SIV requires a 64-byte key")
        cipher = AESSIV(key)
        return cipher.decrypt(ciphertext, [])
    
    if algo == AEADAlgorithm.AES_256_GCM:
        cipher = AESGCM(key[:32])
    elif algo == AEADAlgorithm.CHACHA20_POLY1305:
        cipher = ChaCha20Poly1305(key[:32])
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
    
    return cipher.decrypt(nonce, ciphertext, None)

def encrypt_path(meta_key: bytes, path: str) -> bytes:
    """Encrypt file path"""
    nonce = os.urandom(12)
    cipher = AESGCM(meta_key[:32])
    ciphertext = cipher.encrypt(nonce, path.encode(), b"path")
    return nonce + ciphertext

def decrypt_path(meta_key: bytes, blob: bytes) -> str:
    """Decrypt file path"""
    nonce, ciphertext = blob[:12], blob[12:]
    cipher = AESGCM(meta_key[:32])
    plaintext = cipher.decrypt(nonce, ciphertext, b"path")
    return plaintext.decode()

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Generate Ed25519 keypair for signing"""
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return sk, pk

def sign_manifest(sk: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign manifest data"""
    return sk.sign(data)

def verify_manifest(pk: bytes, signature: bytes, data: bytes):
    """Verify manifest signature"""
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pk)
    public_key.verify(signature, data)