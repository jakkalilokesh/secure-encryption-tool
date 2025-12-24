const SALT_SIZE = 16;
const IV_SIZE = 12;
const ITERATIONS = 100000;

class VaultError extends Error {
    constructor(message) {
        super(message);
        this.name = "VaultError";
    }
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function lockVault(data, password) {
    const enc = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));

    const key = await deriveKey(password, salt);

    const encodedData = enc.encode(JSON.stringify(data));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    const buffer = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
    buffer.set(salt, 0);
    buffer.set(iv, salt.byteLength);
    buffer.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);

    return btoa(String.fromCharCode(...buffer));
}

export async function unlockVault(storedString, password) {
    try {
        const binary = atob(storedString);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }

        if (buffer.length < SALT_SIZE + IV_SIZE) throw new Error("Data too short");

        const salt = buffer.slice(0, SALT_SIZE);
        const iv = buffer.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
        const ciphertext = buffer.slice(SALT_SIZE + IV_SIZE);

        const key = await deriveKey(password, salt);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decrypted));
    } catch (err) {
        throw new VaultError("Incorrect password or corrupted vault.");
    }
}

const STORAGE_KEY = "secure_encryption_tool_vault";

export function loadVaultRaw() {
    return localStorage.getItem(STORAGE_KEY);
}

export function saveVaultRaw(data) {
    localStorage.setItem(STORAGE_KEY, data);
}

export function vaultExists() {
    return !!localStorage.getItem(STORAGE_KEY);
}

let sessionVault = null;

export function getSessionVault() {
    return sessionVault;
}

export function setSessionVault(vault) {
    sessionVault = vault;
}

export function clearSession() {
    sessionVault = null;
}
