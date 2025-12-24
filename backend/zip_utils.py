import io, os, json, base64, zipfile, hashlib, struct, secrets, time
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey, InvalidTag, InvalidSignature
from crypto_core import *

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def encrypt_v2(
    files: List[Tuple[str, bytes]],
    password: str = "",
    algo: str = "aes-256-gcm",
    mode: str = "",
    deterministic: bool = False,
    x25519_pub_b64: str = "",
    rsa_pub_pem: str = "",
    chunk_size: int = 1024 * 1024,
):
    """Simple and reliable encryption"""
    
    if not files:
        raise ValueError("No files provided")
    
    if len(files) > MAX_FILES:
        raise ValueError(f"Too many files (max {MAX_FILES})")
    
    total_size = sum(len(c) for _, c in files)
    if total_size > MAX_TOTAL_SIZE:
        raise ValueError(f"Total size exceeded (max {MAX_TOTAL_SIZE // (1024**3)}GB)")
    
    for name, content in files:
        if len(content) > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {name} (max {MAX_FILE_SIZE // (1024**3)}GB)")
    
    algo_enum = AEADAlgorithm(algo)
    
    if algo_enum == AEADAlgorithm.AES_256_SIV:
        deterministic = True

    master_key = secrets.token_bytes(32)
    
    salt = None
    eph_pub = None
    wrapped_key = None
    
    encrypted_keys = {}
    
    if password and password.strip():
        salt = secrets.token_bytes(16)
        pw_key = derive_password_key(password, salt)
        pw_nonce = secrets.token_bytes(12)
        pw_cipher = AESGCM(pw_key)
        encrypted_keys["password"] = {
            "nonce": base64.b64encode(pw_nonce).decode(),
            "key": base64.b64encode(pw_cipher.encrypt(pw_nonce, master_key, b"master-key")).decode()
        }
    
    if x25519_pub_b64 and x25519_pub_b64.strip():
        try:
            key_bytes = base64.b64decode(x25519_pub_b64.strip())
            if len(key_bytes) != 32:
                 raise ValueError(f"Invalid X25519 key length: expected 32 bytes, got {len(key_bytes)}")

            eph_priv = x25519.X25519PrivateKey.generate()
            eph_pub = eph_priv.public_key()
            
            peer_pub = x25519.X25519PublicKey.from_public_bytes(key_bytes)
            
            shared_secret = eph_priv.exchange(peer_pub)
            x25519_key = hkdf(shared_secret, b"x25519-enc-key")
            
            x25519_nonce = secrets.token_bytes(12)
            x25519_cipher = AESGCM(x25519_key)
            encrypted_keys["x25519"] = {
                "nonce": base64.b64encode(x25519_nonce).decode(),
                "key": base64.b64encode(x25519_cipher.encrypt(x25519_nonce, master_key, b"master-key")).decode()
            }
        except Exception as e:
            raise ValueError(f"Invalid X25519 public key: {str(e)}")
    
    if rsa_pub_pem and rsa_pub_pem.strip():
        try:
            pem_str = rsa_pub_pem.strip()
            if "BEGIN PUBLIC KEY" not in pem_str and "BEGIN RSA PUBLIC KEY" not in pem_str:
                 raise ValueError("Invalid RSA key format: Missing PEM header")

            rsa_pub_key = serialization.load_pem_public_key(pem_str.encode())
            
            wrapped_key = rsa_pub_key.encrypt(
                master_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_keys["rsa"] = {
                "key": base64.b64encode(wrapped_key).decode()
            }
        except Exception as e:
            raise ValueError(f"Invalid RSA public key: {str(e)}")
    
    
    if not encrypted_keys:
        raise ValueError("No encryption keys provided")
    
    key_len = 64 if algo_enum == AEADAlgorithm.AES_256_SIV else 32
    data_key = hkdf(master_key, b"data-key", length=key_len)
    meta_key = hkdf(master_key, b"meta-key", length=32)
    
    ed_sk, ed_pk = generate_ed25519_keypair()
    
    inner = io.BytesIO()
    manifest = []
    
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        for idx, (path, content) in enumerate(files):
            encrypted_path = encrypt_path(meta_key, path)
            file_hash = sha256_hex(content)
            
            chunks = [
                content[i:i + chunk_size]
                for i in range(0, len(content), chunk_size)
            ]
            
            def enc(c):
                nonce = deterministic_nonce(c) if deterministic else None
                return encrypt_chunk(algo_enum, data_key, c, nonce)
            
            out = io.BytesIO()
            with ThreadPoolExecutor() as pool:
                for n, ct in pool.map(enc, chunks):
                    out.write(len(n).to_bytes(1, "big"))
                    out.write(n)
                    out.write(ct)
            
            z.writestr(f"data/file_{idx}.bin", out.getvalue())
            manifest.append({
                "encrypted_path": base64.b64encode(encrypted_path).decode(),
                "sha256": file_hash,
                "algo": algo,
                "original_size": len(content)
            })
    
    mjson = json.dumps({"files": manifest}).encode()
    sig = sign_manifest(ed_sk, mjson)
    
    mn = secrets.token_bytes(12)
    mc = AESGCM(meta_key).encrypt(mn, mjson, b"manifest")
    
    with zipfile.ZipFile(inner, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.bin", mn + mc)
        z.writestr("manifest.sig", sig)
    
    payload_nonce = secrets.token_bytes(12)
    payload = AESGCM(master_key).encrypt(payload_nonce, inner.getvalue(), b"payload")
    
    header = {
        "version": 2,
        "mode": mode,
        "algo": algo,  
        "deterministic": deterministic,
        "chunk_size": chunk_size,
        "wrap_nonce": base64.b64encode(payload_nonce).decode(),
        "ed25519_pub": base64.b64encode(ed_pk).decode(),
        "encrypted_keys": encrypted_keys,
        "integrity_hash": sha256_hex(payload),
        "timestamp": time.time(),
        "file_count": len(files),
        "total_size": total_size
    }
    
    if salt:
        header["salt"] = base64.b64encode(salt).decode()
    if eph_pub:
        header["x25519_ephemeral_pub"] = base64.b64encode(
            eph_pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode()
    if wrapped_key:
        header["rsa_wrapped_key"] = base64.b64encode(wrapped_key).decode()
    
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr("header.json", json.dumps(header, indent=2))
        z.writestr("payload.bin", payload)
    
    return out.getvalue()

def decrypt_v2(bundle, password="", x25519_priv_b64="", rsa_priv_pem=""):
    """Simple and reliable decryption"""
    
    if not bundle:
        raise ValueError("Empty bundle provided")
    
    buf = io.BytesIO(bundle)
    
    with zipfile.ZipFile(buf) as z:
        if "header.json" not in z.namelist():
            raise ValueError("Invalid bundle: missing header.json")
        if "payload.bin" not in z.namelist():
            raise ValueError("Invalid bundle: missing payload.bin")
        
        header = json.loads(z.read("header.json"))
        payload = z.read("payload.bin")
    
    if "integrity_hash" in header:
        computed_hash = sha256_hex(payload)
        if computed_hash != header["integrity_hash"]:
            raise ValueError("Integrity check failed: bundle corrupted")
    
    master_key = None
    
    if master_key is None and "rsa_wrapped_key" in header and rsa_priv_pem and rsa_priv_pem.strip():
        try:
            rsa_sk = serialization.load_pem_private_key(
                rsa_priv_pem.strip().encode(),
                password=None
            )
            wrapped_key = base64.b64decode(header["rsa_wrapped_key"])
            master_key = rsa_sk.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            pass 
            
    if master_key is None and "encrypted_keys" in header:
        if "rsa" in header["encrypted_keys"] and rsa_priv_pem and rsa_priv_pem.strip():
            try:
                rsa_sk = serialization.load_pem_private_key(
                    rsa_priv_pem.strip().encode(),
                    password=None
                )
                rsa_data = header["encrypted_keys"]["rsa"]
                wrapped_key = base64.b64decode(rsa_data["key"])
                master_key = rsa_sk.decrypt(
                    wrapped_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except Exception:
                pass

    if master_key is None and "x25519_ephemeral_pub" in header and x25519_priv_b64 and x25519_priv_b64.strip():
        try:
            priv = x25519.X25519PrivateKey.from_private_bytes(
                base64.b64decode(x25519_priv_b64.strip())
            )
            eph = x25519.X25519PublicKey.from_public_bytes(
                base64.b64decode(header["x25519_ephemeral_pub"])
            )
            shared_secret = priv.exchange(eph)
            x25519_key = hkdf(shared_secret, b"x25519-enc-key")
            
            if "encrypted_keys" in header and "x25519" in header["encrypted_keys"]:
                x25519_data = header["encrypted_keys"]["x25519"]
                x25519_nonce = base64.b64decode(x25519_data["nonce"])
                x25519_enc_key = base64.b64decode(x25519_data["key"])
                x25519_cipher = AESGCM(x25519_key)
                master_key = x25519_cipher.decrypt(x25519_nonce, x25519_enc_key, b"master-key")
        except Exception:
            pass
    
    if master_key is None and "salt" in header and password and password.strip():
        try:
            salt = base64.b64decode(header["salt"])
            pw_key = derive_password_key(password, salt)
            
            if "encrypted_keys" in header and "password" in header["encrypted_keys"]:
                pw_data = header["encrypted_keys"]["password"]
                pw_nonce = base64.b64decode(pw_data["nonce"])
                pw_enc_key = base64.b64decode(pw_data["key"])
                pw_cipher = AESGCM(pw_key)
                master_key = pw_cipher.decrypt(pw_nonce, pw_enc_key, b"master-key")
        except Exception:
            pass
    
    if master_key is None:
        raise ValueError("Unable to decrypt: invalid password or keys")
    
    try:
        inner = AESGCM(master_key).decrypt(
            base64.b64decode(header["wrap_nonce"]),
            payload,
            b"payload",
        )
    except InvalidTag:
        raise ValueError("Decryption failed: invalid key or corrupted data")
    
    algo = header.get("algo", "aes-256-gcm")
    algo_enum = AEADAlgorithm(algo)
    key_len = 64 if algo_enum == AEADAlgorithm.AES_256_SIV else 32
        
    data_key = hkdf(master_key, b"data-key", length=key_len)
    meta_key = hkdf(master_key, b"meta-key", length=32)
    
    results = []
    
    with zipfile.ZipFile(io.BytesIO(inner)) as iz:
        mblob = iz.read("manifest.bin")
        sig = iz.read("manifest.sig")
        
        mn, mc = mblob[:12], mblob[12:]
        manifest_json = AESGCM(meta_key).decrypt(mn, mc, b"manifest")
        
        verify_manifest(
            base64.b64decode(header["ed25519_pub"]),
            sig,
            manifest_json,
        )
        
        manifest = json.loads(manifest_json)
        
        for i, entry in enumerate(manifest["files"]):
            start_time = time.time()
            raw = iz.read(f"data/file_{i}.bin")
            pos = 0
            chunks = []
            
            while pos < len(raw):
                nlen = raw[pos]
                pos += 1
                nonce = raw[pos:pos + nlen]
                pos += nlen
                ct = raw[pos:pos + CHUNK_SIZE + 32]
                pos += len(ct)
                chunks.append((nonce, ct))
            
            def dec(args):
                return decrypt_chunk(
                    AEADAlgorithm(entry["algo"]),
                    data_key,
                    args[0],
                    args[1],
                )
            
            out = io.BytesIO()
            with ThreadPoolExecutor() as pool:
                for pt in pool.map(dec, chunks):
                    out.write(pt)
            
            data = out.getvalue()
            duration = time.time() - start_time
            
            if sha256_hex(data) != entry["sha256"]:
                raise ValueError("Integrity failure")
            
            results.append({
                "path": decrypt_path(meta_key, base64.b64decode(entry["encrypted_path"])),
                "sha256_match": True,
                "path_reconstructed": True,
                "content_b64": base64.b64encode(data).decode(),
                "original_size": entry.get("original_size", len(data)),
                "processing_time": duration,
                "chunk_count": len(chunks),
                "algo": entry.get("algo", algo)
            })
    
    return {"version": 2, "files": results}