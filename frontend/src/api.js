const API_BASE = "http://127.0.0.1:8000";

async function handleResponse(response) {
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      errorMessage = errorData.detail || errorMessage;
    } catch {
      try {
        const text = await response.text();
        if (text) errorMessage = text;
      } catch { }
    }
    throw new Error(errorMessage);
  }
  return response;
}

/**
 * @param {string} route - API route (e.g., "/encrypt/double-rsa")
 * @param {FormData} formData - Form data with files and parameters
 * @returns {Promise<Blob>} - Encrypted bundle as Blob
 */
export async function encryptRequest(route, formData) {
  try {
    const response = await fetch(`${API_BASE}${route}`, {
      method: "POST",
      body: formData,
    });

    await handleResponse(response);

    const contentType = response.headers.get('content-type');
    const contentDisposition = response.headers.get('content-disposition');

    if (!contentType || !contentType.includes('application/zip')) {
      console.warn('Response is not a ZIP file:', contentType);
    }

    let filename = `secure_${Date.now()}.zip`;
    if (contentDisposition) {
      const matches = /filename="([^"]+)"/.exec(contentDisposition);
      if (matches && matches[1]) {
        filename = matches[1];
      } else {
        const matches2 = /filename=([^;]+)/.exec(contentDisposition);
        if (matches2 && matches2[1]) {
          filename = matches2[1];
        }
      }
    }

    const blob = await response.blob();

    if (!blob || blob.size === 0) {
      throw new Error('Received empty response from server');
    }

    blob.filename = filename;

    return blob;
  } catch (error) {
    console.error('Encryption request failed:', error);
    throw error;
  }
}

/**
 * Encrypt with XMLHttpRequest for progress tracking
 * @param {string} route - API route
 * @param {FormData} formData - Form data
 * @param {function} onProgress - Progress callback (0-100)
 * @returns {Promise<Blob>} - Encrypted bundle
 */
export function encryptWithProgress(route, formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.open('POST', `${API_BASE}${route}`);

    xhr.upload.onprogress = (event) => {
      if (onProgress && event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        onProgress(percent);
      }
    };

    xhr.onload = () => {
      if (xhr.status === 200) {
        try {
          const blob = xhr.response;

          const contentDisposition = xhr.getResponseHeader('content-disposition');
          let filename = `secure_${Date.now()}.zip`;
          if (contentDisposition) {
            const matches = /filename="([^"]+)"/.exec(contentDisposition);
            if (matches && matches[1]) {
              filename = matches[1];
            }
          }

          blob.filename = filename;
          resolve(blob);
        } catch (error) {
          reject(new Error('Failed to process response'));
        }
      } else {
        reject(new Error(`Upload failed: ${xhr.status}`));
      }
    };

    xhr.onerror = () => {
      reject(new Error('Network error'));
    };

    xhr.onabort = () => {
      reject(new Error('Request aborted'));
    };

    xhr.responseType = 'blob';
    xhr.send(formData);
  });
}

/**
 * Decrypt bundle
 * @param {FormData} formData - Form data with bundle and keys
 * @returns {Promise<Object>} - Decryption result
 */
export async function decryptRequest(formData) {
  try {
    const response = await fetch(`${API_BASE}/decrypt`, {
      method: "POST",
      body: formData,
    });

    await handleResponse(response);
    return await response.json();
  } catch (error) {
    console.error('Decryption request failed:', error);
    throw error;
  }
}

/**
 * Decrypt with XMLHttpRequest for progress tracking
 * @param {FormData} formData - Form data
 * @param {function} onProgress - Progress callback
 * @returns {Promise<Object>} - Decryption result
 */
export function decryptWithProgress(formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.open('POST', `${API_BASE}/decrypt`);

    xhr.upload.onprogress = (event) => {
      if (onProgress && event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        onProgress(percent);
      }
    };

    xhr.onload = () => {
      if (xhr.status === 200) {
        try {
          const response = JSON.parse(xhr.responseText);
          resolve(response);
        } catch {
          reject(new Error('Invalid response format'));
        }
      } else {
        reject(new Error(`Upload failed: ${xhr.status}`));
      }
    };

    xhr.onerror = () => {
      reject(new Error('Network error'));
    };

    xhr.send(formData);
  });
}

/**
 * Generate X25519 key pair
 * @returns {Promise<Object>} - Keys and metadata
 */
export async function generateX25519Keys() {
  try {
    const response = await fetch(`${API_BASE}/keys/x25519`);
    await handleResponse(response);
    return await response.json();
  } catch (error) {
    console.error('X25519 key generation failed:', error);
    throw error;
  }
}

/**
 * Generate RSA key pair
 * @returns {Promise<Object>} - Keys and metadata
 */
export async function generateRSAKeys() {
  try {
    const response = await fetch(`${API_BASE}/keys/rsa`);
    await handleResponse(response);
    return await response.json();
  } catch (error) {
    console.error('RSA key generation failed:', error);
    throw error;
  }
}

/**
 * Download helper for blobs
 * @param {Blob} blob - Blob to download
 * @param {string} filename - Default filename
 */
export function downloadBlob(blob, filename = 'download.zip') {
  const finalFilename = blob.filename || filename;

  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = finalFilename;

  document.body.appendChild(a);
  a.click();

  setTimeout(() => {
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }, 100);
}

/**
 * Create ZIP from decrypted files
 * @param {Array} files - Array of file objects with path and content_b64
 * @returns {Promise<Blob>} - ZIP blob
 */
export async function createZipFromFiles(files) {
  const JSZip = (await import('jszip')).default;
  const zip = new JSZip();

  files.forEach((f) => {
    const binaryString = atob(f.content_b64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const path = f.path || `file_${Date.now()}`;
    zip.file(path, bytes);
  });

  return await zip.generateAsync({ type: "blob" });
}

/**
 * Health check
 * @returns {Promise<boolean>} - True if backend is healthy
 */
export async function healthCheck() {
  try {
    const response = await fetch(`${API_BASE}/health`, {
      method: 'GET',
      timeout: 5000,
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get security info
 * @returns {Promise<Object|null>} - Security information
 */
export async function getSecurityInfo() {
  try {
    const response = await fetch(`${API_BASE}/security/info`);
    await handleResponse(response);
    return await response.json();
  } catch (error) {
    console.error("Failed to get security info:", error);
    return null;
  }
}

/**
 * Validate encryption parameters
 * @param {string} mode - Encryption mode
 * @param {string} algo - Algorithm
 * @returns {Object} - Validation result
 */
export function validateEncryptionParams(mode, algo) {
  const validModes = [
    "triple", "dual-x25519", "double-x25519",
    "double-rsa", "keyonly-x25519", "keyonly-rsa",
    "password-only"
  ];

  const validAlgos = [
    "aes-256-gcm", "chacha20-poly1305", "aes-256-siv"
  ];

  const errors = [];

  if (!validModes.includes(mode)) {
    errors.push(`Invalid mode. Must be one of: ${validModes.join(', ')}`);
  }

  if (!validAlgos.includes(algo)) {
    errors.push(`Invalid algorithm. Must be one of: ${validAlgos.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create FormData for encryption
 * @param {Array} files - File objects
 * @param {Object} params - Encryption parameters
 * @returns {FormData} - FormData object
 */
export function createEncryptionFormData(files, params) {
  const formData = new FormData();

  files.forEach((file) => {
    formData.append('files', file);
  });

  Object.keys(params).forEach((key) => {
    if (params[key] !== undefined && params[key] !== null) {
      formData.append(key, params[key].toString());
    }
  });

  return formData;
}

/**
 * Test backend connection
 * @returns {Promise<Object>} - Connection status
 */
export async function testConnection() {
  try {
    const startTime = Date.now();
    const isHealthy = await healthCheck();
    const endTime = Date.now();

    return {
      connected: isHealthy,
      latency: endTime - startTime,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      connected: false,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

export function createCancelToken() {
  const controller = new AbortController();
  return {
    signal: controller.signal,
    cancel: () => controller.abort()
  };
}

export class APIError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'APIError';
    this.status = status;
  }
}

export class NetworkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NetworkError';
  }
}

export class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

export default {
  encryptRequest,
  encryptWithProgress,
  decryptRequest,
  decryptWithProgress,
  generateX25519Keys,
  generateRSAKeys,
  downloadBlob,
  createZipFromFiles,
  healthCheck,
  getSecurityInfo,
  validateEncryptionParams,
  createEncryptionFormData,
  testConnection,
  createCancelToken,

  APIError,
  NetworkError,
  ValidationError,

  API_BASE
};

export const hideDataInImage = async (imageFile, secretFile) => {
  const fd = new FormData();
  fd.append("image", imageFile);
  fd.append("file", secretFile);

  const response = await fetch(`${API_BASE}/steg/hide`, {
    method: "POST",
    body: fd,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new APIError(
      errorData.detail || "Steganography hide failed",
      response.status
    );
  }

  return await response.blob();
};

export const revealDataFromImage = async (imageFile) => {
  const fd = new FormData();
  fd.append("image", imageFile);

  const response = await fetch(`${API_BASE}/steg/reveal`, {
    method: "POST",
    body: fd,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new APIError(
      errorData.detail || "Steganography reveal failed",
      response.status
    );
  }

  return await response.blob();
};
