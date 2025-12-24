import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import NeonButton from "../components/NeonButton";
import { healthCheck } from "../api";

export default function Dashboard() {
  const [backendStatus, setBackendStatus] = useState("checking");

  useEffect(() => {
    checkBackend();
  }, []);

  const checkBackend = async () => {
    const isHealthy = await healthCheck();
    setBackendStatus(isHealthy ? "online" : "offline");
  };

  return (
    <div className="text-white">
      <section className="text-center py-16">
        <h1 className="text-5xl font-bold text-cyberGreen mb-4 animate-flicker">
          Secure Encryption Tool
        </h1>
        <p className="text-lg text-gray-300 max-w-3xl mx-auto">
          A high-security encryption suite built for professionals.
          Protect files using X25519, RSA, AES-GCM, AES-SIV & ChaCha20-Poly1305 —
          with multi-layer cryptography and advanced integrity protection.
        </p>

        {/* Backend Status */}
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-6 bg-gray-900/50 mt-4">
          <div className={`w-3 h-3 rounded-full ${backendStatus === 'online' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
          <span className="text-sm">
            Backend: {backendStatus === 'online' ? 'Connected' : 'Disconnected'}
          </span>
          {backendStatus === 'offline' && (
            <button
              onClick={checkBackend}
              className="text-xs text-cyberBlue hover:underline ml-2"
            >
              Retry
            </button>
          )}
        </div>

        <div className="flex justify-center gap-6 mt-10">
          <Link to="/encrypt">
            <NeonButton>Start Encrypting</NeonButton>
          </Link>
          <Link to="/decrypt">
            <NeonButton color="blue">Decrypt Files</NeonButton>
          </Link>
          <Link to="/keys">
            <NeonButton color="purple">Generate Keys</NeonButton>
          </Link>
          <Link to="/steg">
            <NeonButton color="pink">Steganography</NeonButton>
          </Link>
          <Link to="/vault">
            <NeonButton color="green">Key Vault</NeonButton>
          </Link>
        </div>
      </section>

      {/* Feature cards */}
      <section className="grid md:grid-cols-3 gap-8 mt-20">
        {[
          ["Multi-layer Encryption", "Triple, Dual-X25519, RSA-Hybrid"],
          ["High-Security Crypto", "AES-GCM, AES-SIV, ChaCha20-Poly1305"],
          ["Key-Only Modes", "Pure X25519 or RSA Encryption"],
          ["Deterministic Mode", "Nonce-independent AES-SIV"],
          ["Integrity Protection", "Manifest signing via Ed25519"],
          ["Zero-Leak Folder Encryption", "Encrypted file paths & metadata"],
          ["Chunk-Based Processing", "Streaming encryption with configurable chunks"],
          ["Multiprocessing", "Parallel encryption using CPU cores"],
          ["Enhanced KDF", "Scrypt + HKDF-SHA3-256 key derivation"],
        ].map(([title, desc], i) => (
          <div
            key={i}
            className="border border-cyberGreen shadow-neonGreen p-6 rounded-md hover:scale-105 transition"
          >
            <h3 className="text-cyberGreen text-xl font-bold mb-2">{title}</h3>
            <p className="text-gray-300">{desc}</p>
          </div>
        ))}
      </section>

      {/* Stats Section */}
      <section className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="border border-cyberGreen p-4 rounded text-center">
          <div className="text-3xl text-cyberGreen font-bold">256-bit</div>
          <div className="text-gray-400 text-sm">Encryption</div>
        </div>
        <div className="border border-cyberGreen p-4 rounded text-center">
          <div className="text-3xl text-cyberGreen font-bold">10GB</div>
          <div className="text-gray-400 text-sm">Max File Size</div>
        </div>
        <div className="border border-cyberGreen p-4 rounded text-center">
          <div className="text-3xl text-cyberGreen font-bold">Parallel</div>
          <div className="text-gray-400 text-sm">Processing</div>
        </div>
        <div className="border border-cyberGreen p-4 rounded text-center">
          <div className="text-3xl text-cyberGreen font-bold">SHA3-256</div>
          <div className="text-gray-400 text-sm">Integrity</div>
        </div>
      </section>

      {/* Warning Box */}
      <div className="mt-12 p-4 border border-yellow-500 bg-yellow-900/20 rounded">
        <div className="flex items-start">
          <div className="text-yellow-400 text-xl mr-3">⚠</div>
          <div>
            <h3 className="text-yellow-300 font-bold mb-1">Security Notice</h3>
            <p className="text-yellow-200/80 text-sm">
              This tool performs encryption locally. For maximum security:
              <br />• Use strong passwords (12+ characters, mixed case, numbers, symbols)
              <br />• Store private keys securely (password manager recommended)
              <br />• Verify file integrity after encryption/decryption
              <br />• Keep your encryption keys backed up in multiple secure locations
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}