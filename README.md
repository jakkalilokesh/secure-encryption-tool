# 🛡️ Secure Encryption Tool

<div align="center">

![Security Level](https://img.shields.io/badge/Security-High-green?style=for-the-badge)
![Encryption](https://img.shields.io/badge/Encryption-AES%20%7C%20ChaCha20-blue?style=for-the-badge)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Frontend](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)

**A professional-grade, chunk-based file encryption suite built for security and performance.**

</div>

---

## 📋 Overview

Secure Encryption Tool is a web-based application designed to perform secure, client-side-like encryption operations. Unlike simple file lockers, it uses **streamed chunk-based processing**, allowing it to handle huge files (up to 10GB) without eating up RAM.

It supports multiple modern cryptographic primitives including **AES-256-GCM**, **ChaCha20-Poly1305**, and **AES-256-SIV** (for deterministic encryption), along with robust key management using **RSA-4096** and **X25519**.

## ✨ Key Features

- **🔒 Multi-Layer Encryption Modes**:
  - **Triple**: Password + X25519 + RSA (Paranoid security)
  - **Dual**: Password + X25519
  - **Single**: Password-only, Key-only (RSA/X25519)
- **⚡ High Performance**:
  - **Chunked Processing**: Encrypts files of any size (tested up to 10GB).
  - **Parallelism**: Uses `ThreadPoolExecutor` and CPU cores efficiently.
- **🛡️ Advanced Cryptography**:
  - **Algorithms**: AES-256-GCM (Default), ChaCha20-Poly1305 (Mobile/Fast), AES-256-SIV (Deterministic).
  - **KDF**: Scrypt (Memory-hard) for passwords, HKDF-SHA256 for key derivation.
  - **Integrity**: Ed25519 signatures for bundle verification.
  - **Metadata Protection**: Encrypts filenames and directory structure.
- **👁️ Transparent Deterministic Mode**: securely deduplicate files using AES-SIV-256 with 64-byte derived keys.

## 🛠️ Technology Stack

### Backend
- **Language**: Python 3.9+
- **Framework**: FastAPI (Async/Await)
- **Cryptography**: `cryptography` library (OpenSSL bindings), `PyNaCl`
- **Concurrency**: `concurrent.futures`, `asyncio`

### Frontend
- **Framework**: React 18 (Vite)
- **Styling**: Tailwind CSS (Dark/Cyberpunk theme)
- **Components**: `chunk-upload`, `framer-motion` animations

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- Git

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/secure-encryption-tool.git
cd secure-encryption-tool
```

### 2️⃣ Backend Setup
Navigate to the backend directory and set up the environment.

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Start the Backend Server:**
```bash
uvicorn main:app --reload
```
*Backend runs on `http://127.0.0.1:8000`*

### 3️⃣ Frontend Setup
Open a new terminal and navigate to the frontend directory.

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```
*Frontend runs on `http://localhost:3000`*

---

## 📖 Usage Guide

### Encrypting Files
1.  Navigate to the **Encrypt** page.
2.  Drag & drop files or folders (supports multiple files).
3.  Select an **Encryption Mode** (e.g., *Password Only* for simplicity, *Triple* for max security).
4.  (Optional) Select Algorithm (AES-GCM is standard).
5.  Enter Password or paste Keys as required.
6.  Click **Start Encryption**.
7.  A secure `.zip` bundle will be downloaded automatically.

### Decrypting Files
1.  Navigate to the **Decrypt** page.
2.  Upload the encrypted `.zip` bundle.
3.  Enter the Password or Keys used for encryption.
4.  Click **Decrypt**.
5.  The original files will be reconstructed and downloaded.

### Generating Keys
- Go to the **Keys** page to generate secure **X25519 Keypairs** (for fast asymmetric encryption) or **RSA-4096 Keypairs**.
- **Important**: Save your private keys securely! If you lose them, data cannot be recovered.

---

## ⚙️ API Documentation

The backend exposes a REST API (auto-docs available at `/docs` when running).

- `POST /encrypt/{mode}`: Encrypt streams of files.
- `POST /decrypt`: Decrypt a bundle.
- `GET /keys/x25519`: Generate X25519 keypair.
- `GET /keys/rsa`: Generate RSA-4096 keypair.
- `GET /security/info`: Get system security capabilities.

---

## 🚢 Deployment

### Frontend (GitHub Pages / Vercel / Netlify)
Build the frontend static files:
```bash
cd frontend
npm run build
```
Deploy the `dist` folder. Note: If deploying on a different domain than backend, update `API_BASE` in `src/api.js`.

### Backend (AWS / DigitalOcean / Render)
Deploy using Docker or a standard Python environment.

**Systemd Service (Ubuntu/Debian):**
Refere to `backend/deploy/encryption-backend.service` included in the repo for a template.

---

## ⚠️ Security Notice

While this tool uses industry-standard strong cryptography:
1.  **Use HTTPS** in production to protect passwords/keys in transit.
2.  **Private Keys** should never be shared. Use a password manager.
3.  This tool provides **At-Rest Encryption**. The server technically has access to keys during the encryption request (in memory). For pure zero-knowledge, run the backend locally (localhost).

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
