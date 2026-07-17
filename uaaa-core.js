// uaaa-core.js
// -----------------------------------------------------------------------------
// Real asymmetric OpenPGP encryption (via openpgp.js), with the ciphertext bytes
// re-encoded into an alphabet of only 'U' and 'A' characters (prefixed with the
// "UAAA" signature) so the on-page UI and the userscript's page-scanner keep
// working exactly as before.
//
// This file expects the global `openpgp` object to already be loaded on the page
// (see index.html's <script src=".../openpgp.min.js"> and the userscript's
// @require line). It is the single source of truth, shared by both.
// -----------------------------------------------------------------------------

const UAAA_SIG = 'UAAA';

/* ---------------------- U/A bit-alphabet <-> bytes ---------------------- */

function _bytesToUA(bytes) {
    let out = UAAA_SIG;
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        for (let bit = 7; bit >= 0; bit--) {
            out += ((byte >> bit) & 1) ? 'A' : 'U';
        }
    }
    return out;
}

function _uaToBytes(str) {
    let clean = String(str).replace(/[^UA]/gi, '').toUpperCase();
    if (!clean.startsWith(UAAA_SIG)) throw new Error('Missing UAAA signature');
    clean = clean.slice(UAAA_SIG.length);
    if (clean.length === 0) return new Uint8Array(0);
    if (clean.length % 8 !== 0) throw new Error('Corrupt ciphertext length');

    const bytes = new Uint8Array(clean.length / 8);
    for (let i = 0; i < bytes.length; i++) {
        let byte = 0;
        for (let bit = 0; bit < 8; bit++) {
            byte = (byte << 1) | (clean[i * 8 + bit] === 'A' ? 1 : 0);
        }
        bytes[i] = byte;
    }
    return bytes;
}

/* ---------------------------- key generation ----------------------------- */

// Generates a fresh Curve25519 OpenPGP keypair. `passphrase` protects the
// private key at rest (openpgp.js encrypts the private key material with it).
async function UAAAGenerateKeyPair(name, email, passphrase) {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519',
        userIDs: [{ name: name || 'UAAA User', email: email || 'user@uaaa.local' }],
        passphrase: passphrase || undefined,
        format: 'armored'
    });
    return { privateKeyArmored: privateKey, publicKeyArmored: publicKey };
}

/* ------------------------------ encrypt ---------------------------------- */

// Encrypts `plaintext` so only the holder of `recipientPublicKeyArmored`'s
// private key can read it. If a sender private key + passphrase are supplied,
// the message is also signed so the recipient can verify who sent it.
async function UAAAEncrypt(plaintext, recipientPublicKeyArmored, senderPrivateKeyArmored, senderPassphrase) {
    const recipientKey = await openpgp.readKey({ armoredKey: recipientPublicKeyArmored });

    let signingKeys;
    if (senderPrivateKeyArmored) {
        let priv = await openpgp.readPrivateKey({ armoredKey: senderPrivateKeyArmored });
        if (senderPassphrase) {
            priv = await openpgp.decryptKey({ privateKey: priv, passphrase: senderPassphrase });
        }
        signingKeys = priv;
    }

    const message = await openpgp.createMessage({ text: plaintext });
    const encrypted = await openpgp.encrypt({
        message,
        encryptionKeys: recipientKey,
        signingKeys,
        format: 'binary'
    });

    return _bytesToUA(encrypted);
}

/* ------------------------------ decrypt ----------------------------------- */

// Decrypts a UAAA-encoded ciphertext using the reader's own private key.
// If `senderPublicKeyArmored` is supplied, an attached signature is verified.
// Returns { plaintext, verified } where verified is true/false/null
// (null = no signature was present or no sender key was given to check against).
async function UAAADecrypt(uaString, myPrivateKeyArmored, myPassphrase, senderPublicKeyArmored) {
    const bytes = _uaToBytes(uaString);
    if (bytes.length === 0) return { plaintext: '', verified: null };

    const message = await openpgp.readMessage({ binaryMessage: bytes });

    let priv = await openpgp.readPrivateKey({ armoredKey: myPrivateKeyArmored });
    if (myPassphrase) {
        priv = await openpgp.decryptKey({ privateKey: priv, passphrase: myPassphrase });
    }

    let verificationKeys;
    if (senderPublicKeyArmored) {
        verificationKeys = await openpgp.readKey({ armoredKey: senderPublicKeyArmored });
    }

    const { data, signatures } = await openpgp.decrypt({
        message,
        decryptionKeys: priv,
        verificationKeys,
        format: 'utf8'
    });

    let verified = null;
    if (verificationKeys && signatures && signatures.length) {
        try { await signatures[0].verified; verified = true; } catch (e) { verified = false; }
    }

    return { plaintext: data, verified };
}

// Exposed globally for index.html and for the Tampermonkey userscript (@require).
if (typeof window !== 'undefined') {
    window.UAAA = {
        generateKeyPair: UAAAGenerateKeyPair,
        encrypt: UAAAEncrypt,
        decrypt: UAAADecrypt,
        bytesToUA: _bytesToUA,
        uaToBytes: _uaToBytes
    };
}