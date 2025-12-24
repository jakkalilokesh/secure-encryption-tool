from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import io, base64, json, logging, hashlib
from typing import List
from datetime import datetime
import time
from zip_utils import encrypt_v2, decrypt_v2
from cryptography.hazmat.primitives.asymmetric import x25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey, InvalidTag, InvalidSignature

steg_module_available = False
try:
    from steg import hide_data_in_image, reveal_data_from_image
    steg_module_available = True
except ImportError:
    pass

app = FastAPI(
    title="Secure Encryption Tool",
    description="High-security encryption with multiple modes",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if not steg_module_available:
    logger.warning("Steganography module (Pillow) not found. Steg features will be disabled. Install with 'pip install Pillow'.")

request_timestamps = {}

@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    current_time = time.time()
    
    if client_ip in request_timestamps:
        request_timestamps[client_ip] = [
            t for t in request_timestamps[client_ip] 
            if current_time - t < 60
        ]
    
    if client_ip in request_timestamps and len(request_timestamps[client_ip]) >= 30:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please try again in a minute."}
        )
    
    if client_ip not in request_timestamps:
        request_timestamps[client_ip] = []
    request_timestamps[client_ip].append(current_time)
    
    return await call_next(request)

async def read_files(files: List[UploadFile], max_total: int = 10 * 1024 * 1024 * 1024):
    """Read files with validation"""
    file_data = []
    total_size = 0
    
    for file in files:
        content = await file.read()
        total_size += len(content)
        
        if total_size > max_total:
            raise HTTPException(
                status_code=400,
                detail=f"Total file size exceeds {max_total // (1024**3)}GB limit"
            )
        
        file_data.append((file.filename, content))
    
    return file_data

@app.post("/encrypt/{mode}")
async def encrypt(
    mode: str,
    files: List[UploadFile] = File(...),
    password: str = Form(""),
    algo: str = Form("aes-256-gcm"),
    deterministic: bool = Form(False),
    x25519_pub: str = Form(""),
    rsa_pub: str = Form(""),
    chunk_size: int = Form(1024 * 1024),
):
    try:
        logger.info(f"Encryption request: mode={mode}, algo={algo}, files={len(files)}")
        
        valid_modes = ["triple", "dual-x25519", "double-x25519", "double-rsa", 
                      "keyonly-x25519", "keyonly-rsa", "password-only"]
        if mode not in valid_modes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode. Choose from: {', '.join(valid_modes)}"
            )
        
        valid_algos = ["aes-256-gcm", "chacha20-poly1305", "aes-256-siv"]
        if algo not in valid_algos:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid algorithm. Choose from: {', '.join(valid_algos)}"
            )
        
        if algo == "aes-256-siv":
            deterministic = True
        
        file_data = await read_files(files)
        
        if not file_data:
            raise HTTPException(status_code=400, detail="No valid files provided")
        
        bundle = encrypt_v2(
            file_data, 
            password, 
            algo, 
            mode, 
            deterministic,
            x25519_pub if x25519_pub.strip() else "",
            rsa_pub if rsa_pub.strip() else "",
            min(max(chunk_size, 65536), 10 * 1024 * 1024)
        )
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.sha256(bundle[:1000]).hexdigest()[:16]
        filename = f"secure_{timestamp}_{file_hash}.zip"
        
        return StreamingResponse(
            io.BytesIO(bundle),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Content-Hash": hashlib.sha256(bundle).hexdigest()
            }
        )
        
    except ValueError as e:
        logger.error(f"Encryption validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Encryption failed")

@app.post("/decrypt")
async def decrypt(
    bundle: UploadFile = File(...),
    password: str = Form(""),
    x25519_priv: str = Form(""),
    rsa_priv: str = Form(""),
):
    try:
        raw = await bundle.read()
        if not raw:
            raise HTTPException(status_code=400, detail="Empty bundle provided")
        
        logger.info(f"Decryption request: bundle size={len(raw)} bytes")
        
        result = decrypt_v2(raw, password, x25519_priv, rsa_priv)
        
        return JSONResponse({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "file_count": len(result.get("files", [])),
            "integrity_verified": True,
            "files": result.get("files", [])
        })
        
    except ValueError as e:
        error_msg = str(e)
        logger.warning(f"Decryption failed: {error_msg}")
        
        if "invalid key" in error_msg.lower() or "decryption failed" in error_msg.lower():
            raise HTTPException(
                status_code=400, 
                detail="Wrong password or encryption keys. Please verify your inputs."
            )
        elif "rsa" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Invalid RSA private key")
        elif "x25519" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Invalid X25519 private key")
        elif "password" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Invalid password")
        elif "integrity" in error_msg.lower():
            raise HTTPException(status_code=400, detail="File integrity check failed - file may be corrupted")
        else:
            raise HTTPException(status_code=400, detail=error_msg)
            
    except InvalidKey:
        raise HTTPException(status_code=401, detail="Invalid decryption key")
    except InvalidTag:
        raise HTTPException(
            status_code=401, 
            detail="Decryption failed - please check your password and encryption keys are correct."
        )
    except InvalidSignature:
        raise HTTPException(status_code=401, detail="Signature verification failed - file may have been tampered with")
    except Exception as e:
        logger.error(f"Unexpected decryption error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail="Decryption failed due to an internal error"
        )

@app.get("/keys/x25519")
async def gen_x25519():
    try:
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        
        priv_bytes = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        
        priv_fp = hashlib.sha256(priv_bytes).hexdigest()
        pub_fp = hashlib.sha256(pub_bytes).hexdigest()
        
        return {
            "private_key_base64": base64.b64encode(priv_bytes).decode(),
            "public_key_base64": base64.b64encode(pub_bytes).decode(),
            "metadata": {
                "type": "X25519",
                "size": "256-bit",
                "generated": datetime.now().isoformat(),
                "private_fingerprint": priv_fp,
                "public_fingerprint": pub_fp,
                "security_level": "128-bit"
            }
        }
    except Exception as e:
        logger.error(f"X25519 key generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Key generation failed")

@app.get("/keys/rsa")
async def gen_rsa():
    try:
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
            
        )
        
        priv_fp = hashlib.sha256(priv_pem).hexdigest()
        pub_fp = hashlib.sha256(pub_pem).hexdigest()
        
        return {
            "private_key_pem": priv_pem.decode(),
            "public_key_pem": pub_pem.decode(),
            "metadata": {
                "type": "RSA",
                "size": "4096-bit",
                "generated": datetime.now().isoformat(),
                "private_fingerprint": priv_fp,
                "public_fingerprint": pub_fp,
                "security_level": "112-bit"
            }
        }
    except Exception as e:
        logger.error(f"RSA key generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Key generation failed")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Secure Encryption Tool",
        "version": "2.0",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/steg/hide")
async def steg_hide(
    image: UploadFile = File(...),
    file: UploadFile = File(...)
):
    if not steg_module_available:
         raise HTTPException(status_code=501, detail="Steganography module not available (server missing 'Pillow').")

    try:
        cover_image = await image.read()
        secret_data = await file.read()
        
        if len(secret_data) > 10 * 1024 * 1024:
             raise HTTPException(status_code=400, detail="Secret file too large (max 10MB)")
        
        output_png = hide_data_in_image(cover_image, secret_data)
        
        return Response(
            content=output_png,
            media_type="image/png",
            headers={"Content-Disposition": 'attachment; filename="secret_image.png"'}
        )
    except Exception as e:
        logger.error(f"Steg hide error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to hide data: {str(e)}")

@app.post("/steg/reveal")
async def steg_reveal(
    image: UploadFile = File(...)
):
    if not steg_module_available:
         raise HTTPException(status_code=501, detail="Steganography module not available (server missing 'Pillow').")
         
    try:
        steg_image = await image.read()
        secret_data = reveal_data_from_image(steg_image)
        
        return Response(
            content=secret_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": 'attachment; filename="revealed_data.bin"'}
        )
    except Exception as e:
        logger.error(f"Steg reveal error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to reveal data: {str(e)}")

@app.get("/security/info")
async def security_info():
    return {
        "modes": [
            "triple", "dual-x25519", "double-x25519", 
            "double-rsa", "keyonly-x25519", "keyonly-rsa", 
            "password-only"
        ],
        "algorithms": [
            "aes-256-gcm", "chacha20-poly1305", "aes-256-siv"
        ],
        "key_derivation": {
            "primary": "HKDF-SHA256",
            "password": "Scrypt (n=16384, r=8, p=1)"
        },
        "integrity": "Ed25519 Signatures",
        "key_exchange": "X25519"
    }

@app.get("/")
async def root():
    return {
        "message": "Secure Encryption Tool API",
        "version": "2.0",
        "endpoints": {
            "encrypt": "POST /encrypt/{mode}",
            "decrypt": "POST /decrypt",
            "keys/x25519": "GET /keys/x25519",
            "keys/rsa": "GET /keys/rsa",
            "health": "GET /health",
            "security_info": "GET /security/info",
            "steg/hide": "POST /steg/hide",
            "steg/reveal": "POST /steg/reveal"
        }
    }