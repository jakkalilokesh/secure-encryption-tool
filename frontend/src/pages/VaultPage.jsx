import React, { useState, useEffect } from "react";
import NeonButton from "../components/NeonButton";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";
import Toast from "../components/Toast";
import {
    lockVault,
    unlockVault,
    vaultExists,
    loadVaultRaw,
    saveVaultRaw,
    getSessionVault,
    setSessionVault,
    clearSession
} from "../utils/vault";
import { motion, AnimatePresence } from "framer-motion";

export default function VaultPage() {
    const [isSetup, setIsSetup] = useState(false);
    const [isUnlocked, setIsUnlocked] = useState(false);
    const [masterPassword, setMasterPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    const [keys, setKeys] = useState([]);
    const [toast, setToast] = useState(null);

    const [newKeyName, setNewKeyName] = useState("");
    const [newKeyType, setNewKeyType] = useState("RSA");
    const [newKeyValue, setNewKeyValue] = useState("");

    useEffect(() => {
        if (vaultExists()) {
            setIsSetup(true);
            const sess = getSessionVault();
            if (sess) {
                setKeys(sess);
                setIsUnlocked(true);
            }
        }
    }, []);

    const showToast = (message, type = "info") => {
        setToast({ message, type });
    };

    const handleCreateVault = async () => {
        const minLength = 12;
        const hasUpper = /[A-Z]/.test(masterPassword);
        const hasLower = /[a-z]/.test(masterPassword);
        const hasNumber = /[0-9]/.test(masterPassword);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(masterPassword);

        if (masterPassword.length < minLength) {
            showToast(`Password must be at least ${minLength} characters.`, "error");
            return;
        }
        if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
            showToast("Password must contain Uppercase, Lowercase, Number, and Special character.", "error");
            return;
        }

        if (masterPassword !== confirmPassword) {
            showToast("Passwords do not match.", "error");
            return;
        }

        try {
            const emptyVault = [];
            const encrypted = await lockVault(emptyVault, masterPassword);
            saveVaultRaw(encrypted);

            setSessionVault(emptyVault);
            setKeys(emptyVault);
            setIsSetup(true);
            setIsUnlocked(true);
            showToast("Vault created successfully!", "success");
        } catch (err) {
            showToast("Failed to create vault: " + err.message, "error");
        }
    };

    const handleUnlock = async () => {
        if (!masterPassword) {
            showToast("Please enter your Master Password.", "error");
            return;
        }
        try {
            const raw = loadVaultRaw();
            const data = await unlockVault(raw, masterPassword);
            setSessionVault(data);
            setKeys(data);
            setIsUnlocked(true);
            showToast("Vault unlocked.", "success");
            setMasterPassword("");
        } catch (err) {
            showToast("Incorrect password or corrupted vault.", "error");
        }
    };

    const handleLock = () => {
        clearSession();
        setIsUnlocked(false);
        setKeys([]);
        showToast("Vault locked.", "info");
    };

    const handleDeleteVault = () => {
        if (window.confirm("CRITICAL WARNING: This will PERMANENTLY DELETE all your saved keys. There is NO undo. Are you sure?")) {
            localStorage.removeItem("secure_encryption_tool_vault");
            clearSession();
            setIsSetup(false);
            setIsUnlocked(false);
            setKeys([]);
            showToast("Vault deleted and reset.", "warning");
        }
    };

    const handleAddKey = async () => {
        if (!newKeyName || !newKeyValue) {
            showToast("Name and Key Value are required.", "error");
            return;
        }

        const newKey = {
            id: Date.now(),
            name: newKeyName,
            type: newKeyType,
            value: newKeyValue,
            created: new Date().toISOString()
        };

        const updatedKeys = [...keys, newKey];

        const pwd = prompt("Enter Master Password to encrypt and save changes:", "");
        if (!pwd) {
            showToast("Save cancelled.", "info");
            return;
        }

        try {
            // Verify password against current vault first
            const currentRaw = loadVaultRaw();
            if (currentRaw) {
                await unlockVault(currentRaw, pwd);
            }

            const encrypted = await lockVault(updatedKeys, pwd);
            saveVaultRaw(encrypted);

            setKeys(updatedKeys);
            setSessionVault(updatedKeys);

            setNewKeyName("");
            setNewKeyValue("");
            showToast("Key saved securely.", "success");
        } catch (err) {
            showToast("Save failed. Incorrect password?", "error");
        }
    };

    const handleDeleteKey = async (id) => {
        if (!window.confirm("Delete this key?")) return;

        const updatedKeys = keys.filter(k => k.id !== id);

        const pwd = prompt("Enter Master Password to confirm deletion:", "");
        if (!pwd) return;

        try {
            // Verify password against current vault first
            const currentRaw = loadVaultRaw();
            if (currentRaw) {
                await unlockVault(currentRaw, pwd);
            }

            const encrypted = await lockVault(updatedKeys, pwd);
            saveVaultRaw(encrypted);

            setKeys(updatedKeys);
            setSessionVault(updatedKeys);
            showToast("Key deleted.", "success");
        } catch (err) {
            showToast("Delete failed. Incorrect password?", "error");
        }
    };

    return (
        <div className="text-white max-w-4xl mx-auto relative min-h-[600px]">
            <AnimatePresence>
                {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
            </AnimatePresence>

            <h1 className="text-4xl text-cyberGreen font-bold mb-6 flex items-center gap-3">
                🔐 Local Key Vault
            </h1>

            {!isSetup ? (
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-gray-800/50 p-8 rounded-lg border border-gray-700 shadow-2xl">
                    <h2 className="text-2xl font-bold mb-2">Create New Vault</h2>
                    <p className="text-gray-400 mb-6">Create a secure, local-only vault for your encryption keys.</p>

                    <div className="space-y-6 max-w-md">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Master Password</label>
                            <input
                                type="password"
                                placeholder="••••••••••••"
                                className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white focus:border-cyberGreen focus:ring-1 focus:ring-cyberGreen outline-none transition"
                                value={masterPassword}
                                onChange={e => setMasterPassword(e.target.value)}
                            />
                            <div className="mt-2">
                                <PasswordStrengthMeter password={masterPassword} />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Confirm Password</label>
                            <input
                                type="password"
                                placeholder="••••••••••••"
                                className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white focus:border-cyberGreen focus:ring-1 focus:ring-cyberGreen outline-none transition"
                                value={confirmPassword}
                                onChange={e => setConfirmPassword(e.target.value)}
                            />
                        </div>

                        <div className="pt-2">
                            <NeonButton onClick={handleCreateVault} className="w-full">Create Secure Vault</NeonButton>
                        </div>
                    </div>
                </motion.div>
            ) : !isUnlocked ? (
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-gray-800/50 p-8 rounded-lg border border-gray-700 shadow-2xl flex flex-col items-center text-center">
                    <div className="text-6xl mb-4">🔒</div>
                    <h2 className="text-2xl font-bold mb-4">Vault Locked</h2>
                    <div className="space-y-4 max-w-md w-full">
                        <input
                            type="password"
                            placeholder="Enter Master Password"
                            className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white text-center text-lg focus:border-cyberGreen focus:ring-1 focus:ring-cyberGreen outline-none transition"
                            value={masterPassword}
                            onChange={e => setMasterPassword(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleUnlock()}
                            autoFocus
                        />
                        <NeonButton onClick={handleUnlock} className="w-full">Unlock</NeonButton>

                        <div className="mt-8 pt-8 border-t border-gray-700 w-full">
                            <button onClick={handleDeleteVault} className="text-red-500 text-sm hover:text-red-400 transition">
                                Forgot Password? Reset Vault
                            </button>
                        </div>
                    </div>
                </motion.div>
            ) : (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <div className="flex justify-between items-center mb-6 bg-gray-800/30 p-4 rounded border border-gray-700">
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></span>
                            <span className="text-green-400 font-bold">Vault Unlocked</span>
                        </div>
                        <button onClick={handleLock} className="text-gray-400 hover:text-white border px-4 py-2 rounded border-gray-600 hover:bg-gray-700 transition">
                            🔒 Lock Vault
                        </button>
                    </div>

                    <div className="grid gap-4 mb-8">
                        {keys.map(key => (
                            <div key={key.id} className="bg-gray-800 border-l-4 border-cyberGreen p-5 rounded shadow-lg flex justify-between items-center group hover:bg-gray-750 transition-colors">
                                <div className="overflow-hidden">
                                    <div className="flex items-center gap-3 mb-1">
                                        <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase tracking-wider ${key.type === 'RSA' ? 'bg-purple-900 text-purple-200' :
                                            key.type === 'X25519' ? 'bg-blue-900 text-blue-200' :
                                                'bg-yellow-900 text-yellow-200'
                                            }`}>{key.type}</span>
                                        <h3 className="font-bold text-lg">{key.name}</h3>
                                    </div>
                                    <div className="text-xs text-gray-500 font-mono truncate max-w-xl group-hover:text-gray-400 transition-colors">
                                        {key.value.substring(0, 60)}...
                                    </div>
                                </div>
                                <div className="flex gap-3">
                                    <button
                                        onClick={() => { navigator.clipboard.writeText(key.value); showToast("Copied to clipboard!", "info"); }}
                                        className="px-3 py-1 text-sm border border-cyberBlue text-cyberBlue rounded hover:bg-cyberBlue/10 transition"
                                    >
                                        Copy
                                    </button>
                                    <button
                                        onClick={() => handleDeleteKey(key.id)}
                                        className="px-3 py-1 text-sm border border-red-500 text-red-500 rounded hover:bg-red-500/10 transition"
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                        ))}
                        {keys.length === 0 && (
                            <div className="text-gray-500 text-center py-12 border-2 border-dashed border-gray-700 rounded-lg">
                                <div className="text-4xl mb-2">📭</div>
                                No keys stored yet. Add one below.
                            </div>
                        )}
                    </div>

                    <div className="bg-gray-800/80 border border-gray-700 p-8 rounded-lg shadow-xl backdrop-blur-sm">
                        <h3 className="text-xl font-bold mb-6 text-gray-200 flex items-center gap-2">
                            <span className="text-cyberGreen">+</span> Add New Item
                        </h3>
                        <div className="grid gap-6 md:grid-cols-2">
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Name / Label</label>
                                <input
                                    className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white focus:border-cyberGreen outline-none"
                                    placeholder="e.g. My Primary RSA Key"
                                    value={newKeyName}
                                    onChange={e => setNewKeyName(e.target.value)}
                                />
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Type</label>
                                <select
                                    className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white focus:border-cyberGreen outline-none"
                                    value={newKeyType}
                                    onChange={e => setNewKeyType(e.target.value)}
                                >
                                    <option value="RSA">RSA Private Key</option>
                                    <option value="X25519">X25519 Private Key</option>
                                    <option value="Password">Password / Secret</option>
                                </select>
                            </div>
                        </div>
                        <div className="mt-4">
                            <label className="block text-sm text-gray-400 mb-1">Value (Private Key or Password)</label>
                            <textarea
                                className="w-full bg-gray-900 border border-gray-600 p-3 rounded text-white font-mono text-sm h-32 focus:border-cyberGreen outline-none"
                                placeholder="Paste your private key or secret here..."
                                value={newKeyValue}
                                onChange={e => setNewKeyValue(e.target.value)}
                            />
                        </div>
                        <div className="mt-6 flex justify-end items-center gap-4">
                            <p className="text-xs text-gray-500">You will be prompted for Master Password to save.</p>
                            <NeonButton onClick={handleAddKey} color="green" className="px-8">Secure Save</NeonButton>
                        </div>
                    </div>
                </motion.div>
            )}
        </div>
    );
}
