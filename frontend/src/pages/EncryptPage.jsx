import React, { useState, useEffect } from "react";
import FileDropZone from "../components/FileDropZone";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";
import ProgressBar from "../components/ProgressBar";
import NeonButton from "../components/NeonButton";
import {
  encryptWithProgress,
  downloadBlob,
  createEncryptionFormData,
  validateEncryptionParams,
  testConnection
} from "../api";
import { getSessionVault } from "../utils/vault";

const MAX_TOTAL = 10 * 1024 * 1024 * 1024;

export default function EncryptPage() {
  const [files, setFiles] = useState([]);
  const [progress, setProgress] = useState(0);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [status, setStatus] = useState("");
  const [backendStatus, setBackendStatus] = useState({ connected: true, latency: 0 });

  const [mode, setMode] = useState("");
  const [algo, setAlgo] = useState("aes-256-gcm");
  const [chunkSize, setChunkSize] = useState(1024 * 1024);

  const [password, setPassword] = useState("");
  const [x25519Pub, setX25519Pub] = useState("");
  const [rsaPub, setRsaPub] = useState("");

  const [deterministic, setDeterministic] = useState(false);
  const [errors, setErrors] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);

  const [showVaultModal, setShowVaultModal] = useState(false);
  const [vaultTarget, setVaultTarget] = useState("");

  const handleOpenVault = (target) => {
    const vault = getSessionVault();
    if (!vault) {
      alert("Vault is locked or empty. Please unlock it in the Vault page first.");
      return;
    }
    setVaultTarget(target);
    setShowVaultModal(true);
  };

  const handleSelectKey = (key) => {
    if (vaultTarget === 'x25519') setX25519Pub(key.value);
    if (vaultTarget === 'rsa') setRsaPub(key.value);
    setShowVaultModal(false);
  };

  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
  const estimatedChunks = Math.ceil(totalSize / chunkSize);

  const requiresPassword = mode && ["triple", "dual-x25519", "double-x25519", "double-rsa", "password-only"].includes(mode);
  const requiresX25519 = mode && ["triple", "dual-x25519", "double-x25519", "keyonly-x25519"].includes(mode);
  const requiresRSA = mode && ["triple", "double-rsa", "keyonly-rsa"].includes(mode);

  useEffect(() => {
    checkBackendConnection();
  }, []);

  useEffect(() => {
    if (algo !== "aes-256-siv" && deterministic) {
      setDeterministic(false);
    }
  }, [algo, deterministic]);

  const checkBackendConnection = async () => {
    const status = await testConnection();
    setBackendStatus(status);
    if (!status.connected) {
      setErrors(["Backend server is not available. Please start the backend server."]);
    }
  };

  const handleFilesSelected = (incoming) => {
    setFiles((prev) => [...prev, ...incoming]);
    setErrors([]);
  };

  const removeFile = (idx) => {
    setFiles((prev) => prev.filter((_, i) => i !== idx));
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const validateInputs = () => {
    const newErrors = [];

    if (!backendStatus.connected) {
      newErrors.push("Backend server is not available. Please start the backend server.");
      return false;
    }

    if (!files.length) {
      newErrors.push("Please select files first.");
    }

    if (!mode) {
      newErrors.push("Please select encryption mode.");
    }

    if (totalSize > MAX_TOTAL) {
      newErrors.push(`Total size (${formatBytes(totalSize)}) exceeds 10GB limit.`);
    }

    const validation = validateEncryptionParams(mode, algo);
    if (!validation.valid) {
      newErrors.push(...validation.errors);
    }

    if (requiresPassword && !password.trim()) {
      newErrors.push("Password required for selected mode.");
    }

    if (requiresPassword && password.length < 12) {
      newErrors.push("Password must be at least 12 characters.");
    }

    // X25519 Validation
    if (requiresX25519) {
      if (!x25519Pub.trim()) {
        newErrors.push("X25519 public key required.");
      } else {
        try {
          // Check for valid Base64 and length (32 bytes = 44 chars in Base64)
          if (x25519Pub.trim().length !== 44 || !/^[A-Za-z0-9+/]+={0,2}$/.test(x25519Pub.trim())) {
            newErrors.push("Invalid X25519 Public Key. Must be a 32-byte Base64 string (44 chars).");
          }
        } catch (e) {
          newErrors.push("Invalid X25519 Public Key format.");
        }
      }
    }

    // RSA Validation
    if (requiresRSA) {
      if (!rsaPub.trim()) {
        newErrors.push("RSA public key required.");
      } else {
        const pemRegex = /-----BEGIN (?:RSA )?PUBLIC KEY-----\s*[a-zA-Z0-9+/=\s]+\s*-----END (?:RSA )?PUBLIC KEY-----/;
        if (!pemRegex.test(rsaPub.trim())) {
          newErrors.push("Invalid RSA Public Key. Must be a valid PEM format.");
        }
      }
    }

    if (deterministic && algo !== "aes-256-siv") {
      newErrors.push("Deterministic mode is only available with AES-256-SIV.");
    }

    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleEncrypt = async () => {
    setErrors([]);

    if (!validateInputs()) {
      return;
    }

    setIsProcessing(true);

    const params = {
      algo: algo,
      deterministic: deterministic.toString(),
      chunk_size: chunkSize.toString(),
      password: requiresPassword ? password : undefined,
      x25519_pub: requiresX25519 ? x25519Pub : undefined,
      rsa_pub: requiresRSA ? rsaPub : undefined,
    };

    Object.keys(params).forEach(key => {
      if (params[key] === undefined) {
        delete params[key];
      }
    });

    const formData = createEncryptionFormData(files, params);

    try {
      setStatus("Preparing encryption...");
      setProgress(10);

      if (backendStatus.latency > 1000) {
        setStatus(`Preparing encryption... (Connection slow: ${backendStatus.latency}ms)`);
      }

      const blob = await encryptWithProgress(
        `/encrypt/${mode}`,
        formData,
        (uploadPercent) => {
          setUploadProgress(uploadPercent);
          setProgress(10 + (uploadPercent * 0.4));
          setStatus(`Uploading files... ${uploadPercent}%`);
        }
      );

      setProgress(80);
      setStatus("Encrypting files...");

      const processingTime = Math.min(2000, totalSize / (10 * 1024 * 1024));
      await new Promise(resolve => setTimeout(resolve, processingTime));

      setProgress(90);
      setStatus("Creating download...");

      downloadBlob(blob);

      setProgress(100);
      setStatus(`Encryption completed! File: ${blob.filename || 'encrypted.zip'}`);

      setTimeout(() => {
        setProgress(0);
        setUploadProgress(0);
        setStatus(`Success! ${files.length} file(s) encrypted.`);

        setTimeout(() => {
          setStatus("");
          setFiles([]);
          setPassword("");
          setX25519Pub("");
          setRsaPub("");
          setIsProcessing(false);
        }, 2000);
      }, 1000);

    } catch (err) {
      console.error("Encryption error:", err);
      setProgress(0);
      setUploadProgress(0);
      setStatus("Encryption failed");

      if (err.message.includes('NetworkError') || err.message.includes('Failed to fetch')) {
        setErrors(["Network error. Please check your connection and ensure the backend server is running."]);
      } else if (err.message.includes('HTTP 400')) {
        setErrors(["Invalid request. Please check your input parameters."]);
      } else if (err.message.includes('HTTP 401')) {
        setErrors(["Authentication failed. Please check your keys or password."]);
      } else if (err.message.includes('HTTP 500')) {
        setErrors(["Server error. Please try again or contact support."]);
      } else {
        setErrors([err.message || "Encryption failed. Please check your inputs and try again."]);
      }

      setIsProcessing(false);
    }
  };

  const clearAll = () => {
    setFiles([]);
    setPassword("");
    setX25519Pub("");
    setRsaPub("");
    setErrors([]);
    setStatus("");
    setProgress(0);
    setUploadProgress(0);
    setIsProcessing(false);
  };

  const getModeDescription = () => {
    const descriptions = {
      "triple": "Maximum security: Password + X25519 + RSA",
      "dual-x25519": "High security: Password + X25519 key exchange",
      "double-x25519": "X25519 only: Fast with perfect forward secrecy",
      "double-rsa": "RSA only: Compatible with legacy systems",
      "keyonly-x25519": "X25519 only: No password required",
      "keyonly-rsa": "RSA only: No password required",
      "password-only": "Password only: Simple but secure"
    };
    return descriptions[mode] || "";
  };

  return (
    <div className="text-white relative">
      {showVaultModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
          <div className="bg-gray-800 p-6 rounded-lg max-w-md w-full border border-cyberGreen">
            <h3 className="text-xl font-bold mb-4">Select Key from Vault</h3>
            <div className="max-h-60 overflow-y-auto space-y-2">
              {getSessionVault()
                .filter(k => k.type.toUpperCase() === (vaultTarget === 'x25519' ? 'X25519' : 'RSA'))
                .map(k => (
                  <button
                    key={k.id}
                    className="w-full text-left p-3 hover:bg-gray-700 rounded border border-gray-600"
                    onClick={() => handleSelectKey(k)}
                  >
                    <div className="font-bold">{k.name}</div>
                    <div className="text-xs text-gray-400 truncate">{k.value.substring(0, 40)}...</div>
                  </button>
                ))}
              {getSessionVault().filter(k => k.type.toUpperCase() === (vaultTarget === 'x25519' ? 'X25519' : 'RSA')).length === 0 && (
                <div className="text-gray-500 text-center py-4">No matching keys found in vault.</div>
              )}
            </div>
            <button
              onClick={() => setShowVaultModal(false)}
              className="mt-4 text-sm text-red-400 hover:underline w-full text-center"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <h1 className="text-4xl text-cyberGreen font-bold mb-2">Encrypt Files</h1>
      <p className="text-gray-400 mb-6">Secure your files with military-grade encryption</p>

      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full mb-4 text-sm ${backendStatus.connected
        ? 'bg-green-900/30 text-green-400 border border-green-700'
        : 'bg-red-900/30 text-red-400 border border-red-700'
        }`}>
        <div className={`w-2 h-2 rounded-full ${backendStatus.connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
        <span>
          Backend: {backendStatus.connected ? 'Connected' : 'Disconnected'}
          {backendStatus.latency > 0 && backendStatus.connected && ` (${backendStatus.latency}ms)`}
        </span>
        {!backendStatus.connected && (
          <button
            onClick={checkBackendConnection}
            className="text-xs underline ml-2"
          >
            Retry
          </button>
        )}
      </div>

      {errors.length > 0 && (
        <div className="mb-4 p-4 bg-red-900/30 border border-red-500 rounded">
          <div className="flex items-start">
            <div className="text-red-400 text-xl mr-3">⚠</div>
            <div>
              {errors.map((err, idx) => (
                <div key={idx} className="text-red-300 mb-1">• {err}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {status && (
        <div className="mb-4 p-3 bg-blue-900/30 border border-blue-500 rounded text-blue-300">
          {status}
        </div>
      )}

      <div className="mb-6">
        <FileDropZone onFilesSelected={handleFilesSelected} multiple />

        {files.length > 0 && (
          <div className="mt-4 border border-cyberGreen p-4 rounded-md">
            <div className="flex justify-between items-center mb-3">
              <div className="text-cyberGreen font-semibold">Selected Files ({files.length})</div>
              <button
                onClick={() => setFiles([])}
                className="text-sm text-red-400 hover:text-red-300"
                disabled={isProcessing}
              >
                Clear All
              </button>
            </div>

            <div className="max-h-60 overflow-y-auto">
              {files.map((f, i) => (
                <div key={`${f.name}-${i}`} className="flex justify-between items-center py-2 border-b border-gray-700">
                  <div className="flex-1 truncate mr-4" title={f.name}>
                    <span className="text-gray-300">{f.name}</span>
                  </div>
                  <div className="text-gray-400 text-sm whitespace-nowrap">
                    {formatBytes(f.size)}
                  </div>
                  <button
                    onClick={() => removeFile(i)}
                    className="ml-4 text-red-400 hover:text-red-300 px-2 disabled:opacity-50"
                    disabled={isProcessing}
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>

            <div className="mt-3 text-sm text-gray-400">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-gray-500">Total Size:</span> {formatBytes(totalSize)}
                </div>
                <div>
                  <span className="text-gray-500">Estimated Chunks:</span> {estimatedChunks}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="grid md:grid-cols-2 gap-6 mt-8">
        <div>
          <label className="text-cyberGreen block mb-2 font-semibold">
            Encryption Mode <span className="text-red-400">*</span>
          </label>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            className="bg-gray-900"
            disabled={isProcessing}
          >
            <option value="">-- Select Mode --</option>
            <option value="triple">Triple (Password + X25519 + RSA)</option>
            <option value="dual-x25519">Dual (Password + X25519)</option>
            <option value="double-x25519">Double X25519</option>
            <option value="double-rsa">Double RSA</option>
            <option value="keyonly-x25519">X25519 Only</option>
            <option value="keyonly-rsa">RSA Only</option>
            <option value="password-only">Password Only</option>
          </select>
          {mode && (
            <div className="mt-2 text-sm text-gray-400">
              <div className="font-medium">{getModeDescription()}</div>
              <div className="mt-1">
                Requires: {requiresPassword ? 'Password ' : ''}
                {requiresX25519 ? 'X25519 Key ' : ''}
                {requiresRSA ? 'RSA Key' : ''}
              </div>
            </div>
          )}
        </div>

        <div>
          <label className="text-cyberGreen block mb-2 font-semibold">AEAD Algorithm</label>
          <select
            value={algo}
            onChange={(e) => setAlgo(e.target.value)}
            className="bg-gray-900"
            disabled={isProcessing}
          >
            <option value="aes-256-gcm">AES-256-GCM (Recommended)</option>
            <option value="chacha20-poly1305">ChaCha20-Poly1305 (Fast)</option>
            <option value="aes-256-siv">AES-256-SIV (Deterministic)</option>
          </select>
          <div className="mt-2 text-sm text-gray-400">
            {algo === 'aes-256-gcm' && 'Authenticated encryption with good performance'}
            {algo === 'chacha20-poly1305' && 'Fast encryption, good for mobile devices'}
            {algo === 'aes-256-siv' && 'Deterministic encryption, no nonce required'}
          </div>
        </div>
      </div>

      <div className="mt-6">
        <label className="text-cyberGreen block mb-2 font-semibold">Chunk Size</label>
        <div className="flex items-center gap-4">
          <input
            type="range"
            min="65536"
            max="10485760"
            step="65536"
            value={chunkSize}
            onChange={(e) => setChunkSize(parseInt(e.target.value))}
            className="flex-1"
            disabled={isProcessing}
          />
          <div className="text-cyberGreen min-w-[120px] text-lg font-mono">
            {formatBytes(chunkSize)}
          </div>
        </div>
        <div className="flex justify-between text-sm text-gray-400 mt-1">
          <span>64 KB</span>
          <span>10 MB</span>
        </div>
        <div className="text-sm text-gray-400 mt-2">
          {chunkSize <= 256 * 1024
            ? "✓ Fast for many small files (high parallelism)"
            : chunkSize <= 1024 * 1024
              ? "✓ Balanced performance for mixed files"
              : "✓ Best for large individual files (lower memory)"}
        </div>
      </div>

      {requiresPassword && (
        <div className="mt-6">
          <label className="text-cyberGreen block mb-2 font-semibold">
            Password <span className="text-red-400">*</span>
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Minimum 12 characters with uppercase, lowercase, numbers, and symbols"
            className="bg-gray-900"
            disabled={isProcessing}
          />
          <PasswordStrengthMeter password={password} />
          <div className="text-xs text-gray-500 mt-1">
            The password is used with Scrypt KDF (memory-hard) to derive encryption keys.
          </div>
        </div>
      )}

      {requiresX25519 && (
        <div className="mt-6 relative">
          <div className="flex justify-between items-center mb-2">
            <label className="text-cyberGreen font-semibold">
              X25519 Public Key <span className="text-red-400">*</span>
            </label>
            <button onClick={() => handleOpenVault('x25519')} className="text-xs text-cyberBlue border border-cyberBlue px-2 py-0.5 rounded hover:bg-cyberBlue/10">
              Load from Vault
            </button>
          </div>
          <textarea
            rows="3"
            value={x25519Pub}
            onChange={(e) => setX25519Pub(e.target.value)}
            placeholder="Paste X25519 public key (base64, 32 bytes)"
            className="font-mono text-sm bg-gray-900 w-full"
            disabled={isProcessing}
          />
        </div>
      )}

      {requiresRSA && (
        <div className="mt-6">
          <div className="flex justify-between items-center mb-2">
            <label className="text-cyberGreen font-semibold">
              RSA Public Key <span className="text-red-400">*</span>
            </label>
            <button onClick={() => handleOpenVault('rsa')} className="text-xs text-cyberBlue border border-cyberBlue px-2 py-0.5 rounded hover:bg-cyberBlue/10">
              Load from Vault
            </button>
          </div>
          <textarea
            rows="5"
            value={rsaPub}
            onChange={(e) => setRsaPub(e.target.value)}
            placeholder="Paste RSA public key (PEM format, 4096-bit)"
            className="font-mono text-sm bg-gray-900 w-full"
            disabled={isProcessing}
          />
        </div>
      )}

      <div className="mt-6 bg-gray-900/50 p-4 rounded border border-gray-700">
        <label className={`flex items-start gap-3 cursor-pointer ${algo !== "aes-256-siv" || progress > 0 ? "opacity-50 pointer-events-none" : ""}`}>
          <div className="relative flex items-center mt-1">
            <input
              type="checkbox"
              checked={deterministic}
              onChange={(e) => setDeterministic(e.target.checked)}
              disabled={algo !== "aes-256-siv" || progress > 0}
              className="w-5 h-5 accent-cyberGreen bg-gray-800 border-gray-600 rounded focus:ring-cyberGreen"
            />
          </div>
          <div className="flex flex-col">
            <span className={`font-semibold ${algo !== "aes-256-siv" || progress > 0 ? "text-gray-500" : "text-white"}`}>
              Enable Deterministic Mode
            </span>
            <span className="text-gray-400 text-xs mt-1">
              {algo === "aes-256-siv"
                ? "Same plaintext always produces same ciphertext. Useful for deduplication."
                : "Only available with AES-256-SIV algorithm"}
            </span>
          </div>
        </label>
      </div>

      {uploadProgress > 0 && (
        <div className="mt-6">
          <div className="flex justify-between text-sm mb-1">
            <span className="text-gray-400">Upload Progress</span>
            <span className="text-cyberGreen">{uploadProgress}%</span>
          </div>
          <div className="h-2 bg-gray-800 w-full rounded-full">
            <div
              className="h-2 bg-blue-500 rounded-full transition-all duration-300"
              style={{ width: `${uploadProgress}%` }}
            ></div>
          </div>
        </div>
      )}

      {progress > 0 && <ProgressBar progress={progress} label="Overall Progress" />}

      <div className="mt-8 flex flex-wrap gap-4">
        <NeonButton
          onClick={handleEncrypt}
          disabled={isProcessing || !backendStatus.connected || files.length === 0 || !mode}
          className="flex-1 min-w-[200px]"
        >
          {isProcessing ? (
            <span className="flex items-center justify-center gap-2">
              <span className="animate-spin">⟳</span>
              Processing...
            </span>
          ) : (
            "Start Encryption"
          )}
        </NeonButton>

        <button
          onClick={clearAll}
          className="px-6 py-2 border border-gray-600 text-gray-300 rounded-md hover:bg-gray-800 disabled:opacity-50 disabled:cursor-not-allowed"
          disabled={isProcessing}
        >
          Clear All
        </button>

        <button
          onClick={checkBackendConnection}
          className="px-6 py-2 border border-cyberBlue text-cyberBlue rounded-md hover:bg-cyberBlue/10"
        >
          Check Connection
        </button>
      </div>

      <div className="mt-10 border border-cyberGreen p-4 rounded-md bg-gray-900/30">
        <h3 className="text-cyberGreen text-lg font-semibold mb-3">Security Notes</h3>
        <ul className="text-sm text-gray-300 space-y-2">
          <li className="flex items-start">
            <span className="text-cyberGreen mr-2">✓</span>
            <span>All encryption happens locally on your machine. Files are never sent to external servers.</span>
          </li>
          <li className="flex items-start">
            <span className="text-cyberGreen mr-2">✓</span>
            <span>Encryption keys are derived using memory-hard Scrypt KDF to resist brute-force attacks.</span>
          </li>
          <li className="flex items-start">
            <span className="text-cyberGreen mr-2">✓</span>
            <span>File names and metadata are encrypted to prevent information leakage.</span>
          </li>
          <li className="flex items-start">
            <span className="text-cyberGreen mr-2">✓</span>
            <span>Ed25519 signatures ensure bundle integrity and authenticity.</span>
          </li>
          <li className="flex items-start">
            <span className="text-cyberGreen mr-2">⚠</span>
            <span>Keep your private keys secure. Losing keys means permanent data loss.</span>
          </li>
        </ul>
      </div>
    </div>
  );
}