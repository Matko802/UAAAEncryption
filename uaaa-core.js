// uaaa-core.js - Base64 Encryption Engine
/**
 * UAAA Encryption System
 * Uses XOR cipher + Base64 Encoding
 * @param {string} t - Text to encrypt/decrypt
 * @param {string} k - Encryption key
 * @param {boolean} e - True to encrypt, false to decrypt
 * @returns {string} - Encrypted or decrypted text
 */
function _C(t, k, e) {
    const _s = '\x55\x41\x41\x41'; // Magic: "UAAA"
    
    // Input validation
    if (typeof t !== 'string') throw new TypeError('Input must be a string');
    if (typeof k !== 'string' || !k.length) throw new TypeError('Key must be non-empty string');
    if (!t.length && e) return _s; // Handle empty input for encryption
    
    if (e) {
        // === ENCRYPTION ===
        // Convert to UTF-8 to handle special characters
        let utf8Str = encodeURIComponent(t).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1));
        
        let xored = '';
        for (let i = 0; i < utf8Str.length; i++) {
            xored += String.fromCharCode(utf8Str.charCodeAt(i) ^ k.charCodeAt(i % k.length));
        }
        
        // Base64 encode the XOR'd string
        return _s + btoa(xored);
    } else {
        // === DECRYPTION ===
        if (!t.startsWith(_s)) throw new Error('Invalid cipher signature');
        
        let b64Str = t.substring(_s.length);
        let xored = '';
        
        try {
            xored = atob(b64Str);
        } catch (err) {
            throw new Error('Invalid Base64 payload');
        }
        
        let decrypted = '';
        for (let i = 0; i < xored.length; i++) {
            decrypted += String.fromCharCode(xored.charCodeAt(i) ^ k.charCodeAt(i % k.length));
        }
        
        // Convert back from UTF-8
        try {
            return decodeURIComponent(decrypted.split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        } catch (err) {
            return decrypted; // Fallback if conversion fails
        }
    }
}
