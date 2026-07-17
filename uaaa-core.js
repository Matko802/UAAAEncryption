// uaaa-core.js - AES-256-GCM Encryption Engine (U/A Encoding)
/**
 * UAAA Encryption System
 * Uses true AES-256-GCM via Web Crypto API with U/A Binary Encoding
 * @param {string} t - Text to encrypt/decrypt
 * @param {string} k - Encryption key
 * @param {boolean} e - True to encrypt, false to decrypt
 * @returns {Promise<string>} - Encrypted or decrypted text
 */

// Helper to convert ArrayBuffer to U/A binary string
function _buf2UA(buffer) {
    let ua = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        let bin = bytes[i].toString(2).padStart(8, '0');
        for (let j = 0; j < 8; j++) {
            ua += (bin[j] === '0') ? 'U' : 'A';
        }
    }
    return ua;
}

// Helper to convert U/A binary string to ArrayBuffer
function _UA2buf(uaStr) {
    if (uaStr.length % 8 !== 0) throw new Error('Invalid UA payload length');
    const bytes = new Uint8Array(uaStr.length / 8);
    for (let i = 0; i < bytes.byteLength; i++) {
        let chunk = uaStr.substring(i * 8, (i * 8) + 8);
        let bin = chunk.replace(/U/g, '0').replace(/A/g, '1');
        bytes[i] = parseInt(bin, 2);
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
    
    if (typeof t !== 'string') throw new TypeError('Input must be a string');
    if (typeof k !== 'string' || !k.length) throw new TypeError('Key must be non-empty string');
    if (!t.length && e) return _s;
    if (!crypto || !crypto.subtle) throw new Error('Web Crypto API not supported in this context (HTTPS required)');

    const cryptoKey = await _deriveKey(k);
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    if (e) {
        // === ENCRYPTION ===
        const iv = crypto.getRandomValues(new Uint8Array(12)); 
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            cryptoKey,
            enc.encode(t)
        );
        
        const payload = new Uint8Array(12 + ciphertext.byteLength);
        payload.set(iv, 0);
        payload.set(new Uint8Array(ciphertext), 12);
        
        return _s + _buf2UA(payload.buffer);
    } else {
        // === DECRYPTION ===
        let cleanText = t.replace(/\s/g, '').toUpperCase();
        if (!cleanText.startsWith(_s)) throw new Error('Invalid cipher signature');
        
        let uaStr = cleanText.substring(_s.length);
        if (!/^[UA]+$/.test(uaStr)) throw new Error('Ciphertext contains invalid characters');
        
        let payloadBuffer;
        try {
            payloadBuffer = _UA2buf(uaStr);
        } catch (err) {
            throw new Error('Invalid UA payload structure');
        }
        
        if (payloadBuffer.byteLength < 12) throw new Error('Payload too short or corrupt');

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
