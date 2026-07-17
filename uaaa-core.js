// uaaa-core.js - AES-256-GCM Encryption Engine
/**
 * UAAA Encryption System
 * Uses true AES-256-GCM via Web Crypto API
 * @param {string} t - Text to encrypt/decrypt
 * @param {string} k - Encryption key
 * @param {boolean} e - True to encrypt, false to decrypt
 * @returns {Promise<string>} - Encrypted or decrypted text
 */

// Helper to convert ArrayBuffer to Base64
function _buf2b64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Helper to convert Base64 to ArrayBuffer
function _b642buf(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Derives a 256-bit AES key using SHA-256 hash of the provided string key
async function _deriveKey(password) {
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest("SHA-256", enc.encode(password));
    return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function _C(t, k, e) {
    const _s = '\x55\x41\x41\x41\x41'; // Magic: "UAAAA"
    
    // Input validation
    if (typeof t !== 'string') throw new TypeError('Input must be a string');
    if (typeof k !== 'string' || !k.length) throw new TypeError('Key must be non-empty string');
    if (!t.length && e) return _s;
    if (!crypto || !crypto.subtle) throw new Error('Web Crypto API not supported in this context (HTTPS required)');

    const cryptoKey = await _deriveKey(k);
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    if (e) {
        // === ENCRYPTION ===
        const iv = crypto.getRandomValues(new Uint8Array(12)); // Secure random IV
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            enc.encode(t)
        );
        
        // Bundle IV and Ciphertext together for extraction during decryption
        const payload = new Uint8Array(12 + ciphertext.byteLength);
        payload.set(iv, 0);
        payload.set(new Uint8Array(ciphertext), 12);
        
        return _s + _buf2b64(payload.buffer);
    } else {
        // === DECRYPTION ===
        if (!t.startsWith(_s)) throw new Error('Invalid cipher signature');
        
        let b64Str = t.substring(_s.length);
        let payloadBuffer;
        
        try {
            payloadBuffer = _b642buf(b64Str);
        } catch (err) {
            throw new Error('Invalid Base64 payload');
        }
        
        if (payloadBuffer.byteLength < 12) throw new Error('Payload too short or corrupt');

        // Extract IV and Ciphertext
        const iv = payloadBuffer.slice(0, 12);
        const ciphertext = payloadBuffer.slice(12);

        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                cryptoKey,
                ciphertext
            );
            return dec.decode(decrypted);
        } catch (err) {
            throw new Error('Authentication failed (Wrong key or corrupted data)');
        }
    }
}
