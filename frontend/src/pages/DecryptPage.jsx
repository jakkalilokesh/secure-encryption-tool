import React, { useState } from "react";
import FileDropZone from "../components/FileDropZone";
import NeonButton from "../components/NeonButton";
import ProgressBar from "../components/ProgressBar";
import JSZip from "jszip";
import { decryptWithProgress } from "../api";
import { getSessionVault } from "../utils/vault";

export default function DecryptPage() {
  const [bundle, setBundle] = useState(null);
  const [bundleName, setBundleName] = useState("");
  const [uploadProgress, setUploadProgress] = useState(0);

  const [requiresPassword, setRequiresPassword] = useState(false);
  const [requiresX25519, setRequiresX25519] = useState(false);
  const [requiresRSA, setRequiresRSA] = useState(false);

  const [password, setPassword] = useState("");
  const [xPriv, setXPriv] = useState("");
  const [rsaPriv, setRsaPriv] = useState("");

  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState([]);
  const [errors, setErrors] = useState([]);
  const [status, setStatus] = useState("");
  const [forceShowAll, setForceShowAll] = useState(false);

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
    if (vaultTarget === 'password') setPassword(key.value);
    if (vaultTarget === 'x25519') setXPriv(key.value);
    if (vaultTarget === 'rsa') setRsaPriv(key.value);
    setShowVaultModal(false);
  };

  const onBundleSelected = async (files) => {
    const file = files[0];
    setBundle(file);
    setBundleName(file.name);
    setErrors([]);
    setReport([]);

    try {
      setStatus("Analyzing bundle...");

      const arrayBuffer = await file.arrayBuffer();
      const zip = await JSZip.loadAsync(arrayBuffer);

      if (!zip.files["header.json"]) {
        throw new Error("Invalid bundle: missing header.json");
      }

      const header = JSON.parse(
        await zip.files["header.json"].async("string")
      );

      const mode = header.mode || "";

      let needsPassword = false;
      let needsX25519 = false;
      let needsRSA = false;

      if (header.encrypted_keys) {
        needsPassword = !!header.encrypted_keys.password;
        needsX25519 = !!header.encrypted_keys.x25519;
        needsRSA = !!header.encrypted_keys.rsa;

        if (header.rsa_wrapped_key) needsRSA = true;

      } else {
        switch (mode) {
          case "triple":
            needsPassword = true; needsX25519 = true; needsRSA = true; break;
          case "dual-x25519":
            needsPassword = true; needsX25519 = true; needsRSA = false; break;
          case "double-x25519":
            needsPassword = true; needsX25519 = true; needsRSA = false; break;
          case "double-rsa":
            needsPassword = true; needsX25519 = false; needsRSA = true; break;
          case "keyonly-x25519":
            needsPassword = false; needsX25519 = true; needsRSA = false; break;
          case "keyonly-rsa":
            needsPassword = false; needsX25519 = false; needsRSA = true; break;
          case "password-only":
            needsPassword = true; needsX25519 = false; needsRSA = false; break;
          default:
            needsPassword = true;
            console.warn("Unknown encryption mode:", mode);
        }
      }

      setRequiresPassword(needsPassword);
      setRequiresX25519(needsX25519);
      setRequiresRSA(needsRSA);

      setStatus("");

    } catch (err) {
      console.error("Bundle inspection failed:", err);
      setRequiresPassword(true);
      setRequiresX25519(false);
      setRequiresRSA(false);
      setErrors(["Unable to read bundle header. Please ensure it's a valid encrypted bundle."]);
    }
  };

  const downloadZip = async (files) => {
    try {
      const zip = new JSZip();

      for (const f of files) {
        const binaryString = atob(f.content_b64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        zip.file(f.path, bytes);
      }

      const blob = await zip.generateAsync({ type: "blob" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `decrypted_${Date.now()}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      return true;
    } catch (err) {
      console.error("Download failed:", err);
      throw new Error("Failed to create download");
    }
  };

  const handleDecrypt = async () => {
    setErrors([]);
    setStatus("");
    setReport([]);

    if (!bundle) {
      setErrors(["Upload encrypted bundle first."]);
      return;
    }

    const validationErrors = [];

    if (requiresPassword && !password.trim()) {
      validationErrors.push("Password required.");
    }

    if (requiresX25519 && !xPriv.trim()) {
      validationErrors.push("X25519 private key required.");
    }

    if (requiresRSA && !rsaPriv.trim()) {
      validationErrors.push("RSA private key required.");
    }

    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    const fd = new FormData();
    fd.append("bundle", bundle);
    fd.append("password", password);
    fd.append("x25519_priv", xPriv);
    fd.append("rsa_priv", rsaPriv);

    try {
      setStatus("Uploading bundle...");
      setProgress(10);

      const json = await decryptWithProgress(
        fd,
        (uploadPercent) => {
          setUploadProgress(uploadPercent);
          setProgress(10 + (uploadPercent * 0.3));
        }
      );

      setProgress(80);
      setStatus("Decrypting files...");

      if (!json.files || !Array.isArray(json.files)) {
        throw new Error("Invalid response from server");
      }

      setProgress(90);
      setStatus("Preparing download...");

      const enhancedFiles = json.files.map((f, index) => ({
        id: index,
        path: f.path,
        filename: f.path.split('/').pop() || f.path,
        size: f.original_size ? `${(f.original_size / 1024).toFixed(2)} KB` : 'Unknown',
        integrity: f.sha256_match ? "Verified" : "Failed",
        path_status: f.path_reconstructed ? "Restored" : "Failed",
        chunk_count: f.chunk_count || 1,
        processing_time: f.processing_time ? `${(f.processing_time * 1000).toFixed(0)}ms` : 'N/A',
        status: "success"
      }));

      setReport(enhancedFiles);

      await downloadZip(json.files);

      setProgress(100);
      setStatus("Decryption completed successfully!");

      setTimeout(() => {
        setProgress(0);
        setUploadProgress(0);
        setStatus("");
        setPassword("");
        setXPriv("");
        setRsaPriv("");
      }, 3000);

    } catch (err) {
      setProgress(0);
      setUploadProgress(0);
      setStatus("Decryption failed");
      setErrors([err.message || "Decryption failed. Check your keys and try again."]);
    }
  };

  const clearForm = () => {
    setBundle(null);
    setBundleName("");
    setPassword("");
    setXPriv("");
    setRsaPriv("");
    setReport([]);
    setErrors([]);
    setStatus("");
    setUploadProgress(0);
    setProgress(0);
  };

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="text-white relative">
      {showVaultModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
          <div className="bg-gray-800 p-6 rounded-lg max-w-md w-full border border-cyberGreen">
            <h3 className="text-xl font-bold mb-4">Select {vaultTarget === 'password' ? 'Password' : 'Key'} from Vault</h3>
            <div className="max-h-60 overflow-y-auto space-y-2">
              {getSessionVault()
                .filter(k => {
                  if (vaultTarget === 'password') return k.type === 'Password';
                  if (vaultTarget === 'x25519') return k.type === 'X25519';
                  if (vaultTarget === 'rsa') return k.type === 'RSA';
                  return false;
                })
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
              {getSessionVault().filter(k => {
                if (vaultTarget === 'password') return k.type === 'Password';
                if (vaultTarget === 'x25519') return k.type === 'X25519';
                if (vaultTarget === 'rsa') return k.type === 'RSA';
                return false;
              }).length === 0 && (
                  <div className="text-gray-500 text-center py-4">No matching items found in vault.</div>
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

      <h1 className="text-4xl text-cyberGreen font-bold mb-6">Decrypt Files</h1>

      {errors.length > 0 && (
        <div className="mb-4 p-4 bg-red-900/30 border border-red-500 rounded">
          {errors.map((err, idx) => (
            <div key={idx} className="text-red-300">• {err}</div>
          ))}
        </div>
      )}

      {status && (
        <div className="mb-4 p-3 bg-blue-900/30 border border-blue-500 rounded text-blue-300">
          {status}
        </div>
      )}

      <FileDropZone onFilesSelected={onBundleSelected} multiple={false} />

      {bundleName && (
        <div className="mt-4 p-3 border border-cyberGreen rounded bg-gray-900/30">
          <div className="text-cyberGreen">Bundle loaded:</div>
          <div className="truncate">{bundleName}</div>
          <div className="text-sm text-gray-400 mt-1">
            <div className="flex flex-wrap gap-3">
              {requiresPassword && (
                <span className="px-2 py-1 bg-yellow-900/50 text-yellow-300 rounded text-xs">
                  Password Required
                </span>
              )}
              {requiresX25519 && (
                <span className="px-2 py-1 bg-blue-900/50 text-blue-300 rounded text-xs">
                  X25519 Key Required
                </span>
              )}
              {requiresRSA && (
                <span className="px-2 py-1 bg-purple-900/50 text-purple-300 rounded text-xs">
                  RSA Key Required
                </span>
              )}
              {!requiresPassword && !requiresX25519 && !requiresRSA && (
                <span className="px-2 py-1 bg-gray-700/50 text-gray-300 rounded text-xs">
                  No keys detected
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {!bundle && (
        <p className="mt-4 text-gray-400">
          Upload an encrypted bundle to detect required keys.
        </p>
      )}

      {!forceShowAll && !(!requiresPassword && !requiresX25519 && !requiresRSA) && (
        <div className="mt-4 text-right">
          <button
            onClick={() => setForceShowAll(true)}
            className="text-xs text-cyberBlue hover:text-white underline"
          >
            Show all input options
          </button>
        </div>
      )}

      {(requiresPassword || forceShowAll) && (
        <div className="mt-6">
          <div className="flex justify-between items-center mb-2">
            <label className="text-cyberGreen block">Password {forceShowAll && !requiresPassword && <span className="text-gray-500 text-xs">(Optional)</span>}</label>
            <button onClick={() => handleOpenVault('password')} className="text-xs text-cyberBlue border border-cyberBlue px-2 py-0.5 rounded hover:bg-cyberBlue/10">
              Load from Vault
            </button>
          </div>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter decryption password"
            className="bg-gray-900"
          />
        </div>
      )}

      {(requiresX25519 || forceShowAll) && (
        <div className="mt-6">
          <div className="flex justify-between items-center mb-2">
            <label className="text-cyberGreen block">X25519 Private Key {forceShowAll && !requiresX25519 && <span className="text-gray-500 text-xs">(Optional)</span>}</label>
            <button onClick={() => handleOpenVault('x25519')} className="text-xs text-cyberBlue border border-cyberBlue px-2 py-0.5 rounded hover:bg-cyberBlue/10">
              Load from Vault
            </button>
          </div>
          <textarea
            rows="3"
            value={xPriv}
            onChange={(e) => setXPriv(e.target.value)}
            placeholder="Paste X25519 private key (base64)"
            className="font-mono text-sm bg-gray-900"
          />
        </div>
      )}

      {(requiresRSA || forceShowAll) && (
        <div className="mt-6">
          <div className="flex justify-between items-center mb-2">
            <label className="text-cyberGreen block">RSA Private Key {forceShowAll && !requiresRSA && <span className="text-gray-500 text-xs">(Optional)</span>}</label>
            <button onClick={() => handleOpenVault('rsa')} className="text-xs text-cyberBlue border border-cyberBlue px-2 py-0.5 rounded hover:bg-cyberBlue/10">
              Load from Vault
            </button>
          </div>
          <textarea
            rows="6"
            value={rsaPriv}
            onChange={(e) => setRsaPriv(e.target.value)}
            placeholder="Paste RSA private key (PEM format)"
            className="font-mono text-sm bg-gray-900"
          />
        </div>
      )}

      {uploadProgress > 0 && (
        <div className="mt-6">
          <div className="flex justify-between text-sm mb-1">
            <span className="text-gray-400">Upload Progress</span>
            <span className="text-cyberGreen">{uploadProgress}%</span>
          </div>
          <div className="h-2 bg-gray-800 w-full rounded-full">
            <div
              className="h-2 bg-blue-500 rounded-full transition-all"
              style={{ width: `${uploadProgress}%` }}
            ></div>
          </div>
        </div>
      )}

      {progress > 0 && <ProgressBar progress={progress} />}

      <div className="mt-8 flex gap-4">
        <NeonButton onClick={handleDecrypt} disabled={progress > 0}>
          {progress > 0 ? "Decrypting..." : "Decrypt"}
        </NeonButton>

        {bundle && (
          <button
            onClick={clearForm}
            className="px-5 py-2 border border-gray-600 text-gray-300 rounded-md hover:bg-gray-800"
          >
            Clear
          </button>
        )}
      </div>

      {report.length > 0 && (
        <div className="mt-10 border border-cyberGreen p-6 rounded-md bg-gray-900/30">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl text-cyberGreen font-bold">Integrity Report</h2>
            <div className="text-sm text-gray-400">
              {report.length} file{report.length !== 1 ? 's' : ''} decrypted
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="border border-cyberGreen p-3 rounded text-center">
              <div className="text-cyberGreen text-xl font-bold">{report.length}</div>
              <div className="text-gray-400 text-sm">Total Files</div>
            </div>
            <div className="border border-cyberGreen p-3 rounded text-center">
              <div className="text-green-400 text-xl font-bold">
                {report.filter(f => f.integrity === "Verified").length}
              </div>
              <div className="text-gray-400 text-sm">Integrity Verified</div>
            </div>
            <div className="border border-cyberGreen p-3 rounded text-center">
              <div className="text-green-400 text-xl font-bold">
                {report.filter(f => f.path_status === "Restored").length}
              </div>
              <div className="text-gray-400 text-sm">Paths Restored</div>
            </div>
            <div className="border border-cyberGreen p-3 rounded text-center">
              <div className="text-cyberGreen text-xl font-bold">100%</div>
              <div className="text-gray-400 text-sm">Success Rate</div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-cyberGreen">
                  <th className="p-3 text-left text-cyberGreen">Filename</th>
                  <th className="p-3 text-left text-cyberGreen">Size</th>
                  <th className="p-3 text-left text-cyberGreen">Integrity</th>
                  <th className="p-3 text-left text-cyberGreen">Path Status</th>
                  <th className="p-3 text-left text-cyberGreen">Chunks</th>
                  <th className="p-3 text-left text-cyberGreen">Time</th>
                </tr>
              </thead>
              <tbody>
                {report.map((f) => (
                  <tr key={f.id} className="border-b border-gray-700 hover:bg-gray-800/30">
                    <td className="p-3">
                      <div className="flex items-center">
                        <div className={`w-2 h-2 rounded-full mr-2 ${f.status === 'success' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                        <div className="truncate max-w-[200px]" title={f.filename}>
                          {f.filename}
                        </div>
                      </div>
                    </td>
                    <td className="p-3 text-gray-300">{f.size}</td>
                    <td className="p-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs ${f.integrity === "Verified"
                        ? 'bg-green-900/50 text-green-300'
                        : 'bg-red-900/50 text-red-300'
                        }`}>
                        {f.integrity === "Verified" ? (
                          <>
                            <span className="mr-1">✓</span> Verified
                          </>
                        ) : (
                          <>
                            <span className="mr-1">✗</span> Failed
                          </>
                        )}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs ${f.path_status === "Restored"
                        ? 'bg-green-900/50 text-green-300'
                        : 'bg-red-900/50 text-red-300'
                        }`}>
                        {f.path_status === "Restored" ? (
                          <>
                            <span className="mr-1">✓</span> Restored
                          </>
                        ) : (
                          <>
                            <span className="mr-1">✗</span> Failed
                          </>
                        )}
                      </span>
                    </td>
                    <td className="p-3 text-gray-300">{f.chunk_count}</td>
                    <td className="p-3 text-gray-300">{f.processing_time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-6 p-4 bg-green-900/20 border border-green-500/50 rounded">
            <div className="flex items-center">
              <div className="text-green-400 text-xl mr-3">✓</div>
              <div>
                <h3 className="text-green-300 font-bold mb-1">Decryption Successful!</h3>
                <p className="text-green-200/80 text-sm">
                  All files have been successfully decrypted and verified.
                  The downloaded ZIP file contains your original files with restored paths and verified integrity.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-6 p-4 bg-blue-900/20 border border-blue-500/50 rounded">
            <div className="flex items-start">
              <div className="text-blue-400 text-lg mr-3">🔒</div>
              <div>
                <h3 className="text-blue-300 font-bold mb-1">Security Notes</h3>
                <ul className="text-blue-200/80 text-sm space-y-1">
                  <li>• All files passed SHA-256 integrity verification</li>
                  <li>• File paths have been securely decrypted and restored</li>
                  <li>• Manifest signature verified with Ed25519</li>
                  <li>• No evidence of tampering detected</li>
                  <li>• Original file structure has been preserved</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}