// ==UserScript==
// @name         UAAADecryptor
// @namespace    http://tampermonkey.net/
// @version      0.1.0
// @description  UAAAEncryption custom encryptor/decryptor (now real asymmetric OpenPGP under the hood)
// @author       Matko802
// @match        *://*/*
// @require      https://unpkg.com/openpgp@6/dist/openpgp.min.js
// @require      https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/uaaa-core.js
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_registerMenuCommand
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const ENCRYPTOR_URL = 'https://matko802.github.io/UAAAEncryption/';
    const CIPHER_REGEX = /(UAAA[UA]+)/gi;

    // The UAAA.encrypt/UAAA.decrypt engine is injected by the @require tags above
    // (openpgp.js first, then uaaa-core.js which wraps it).

    /* ---------------------------------------------------------------------
       Key setup, via the Tampermonkey menu. Your PRIVATE key + passphrase
       are only ever asked for at decrypt-time (the passphrase is never
       stored) — only the armored private key itself sits in GM storage,
       scoped to this script, and is still passphrase-protected at rest.
    --------------------------------------------------------------------- */
    GM_registerMenuCommand('🔑 Set My Private Key (paste armored key)', () => {
        const current = GM_getValue('uaaa_my_private', '');
        const pasted = prompt('Paste your ARMORED PRIVATE KEY (from the UAAA site\'s "Keys" panel):', current);
        if (pasted !== null) GM_setValue('uaaa_my_private', pasted.trim());
    });

    GM_registerMenuCommand('🧾 Set My Public Key (for reference)', () => {
        const current = GM_getValue('uaaa_my_public', '');
        const pasted = prompt('Paste your ARMORED PUBLIC KEY (so you can copy it back out later):', current);
        if (pasted !== null) GM_setValue('uaaa_my_public', pasted.trim());
    });

    GM_registerMenuCommand('🗑️ Clear My Stored Keys', () => {
        if (confirm('Remove your stored private/public key from this script\'s storage?')) {
            GM_deleteValue('uaaa_my_private');
            GM_deleteValue('uaaa_my_public');
        }
    });

    function applyStyle(el, color, bg, border) {
        el.style.color = color;
        el.style.backgroundColor = bg;
        el.style.border = `1px solid ${border}`;
        el.style.padding = '2px 6px';
        el.style.borderRadius = '0px';
        el.style.fontSize = '0.75em';
        el.style.fontFamily = 'Courier New, monospace';
        el.style.fontWeight = 'bold';
        el.style.cursor = 'pointer';
        el.style.outline = 'none';
        el.style.display = 'inline-block';
        el.style.userSelect = 'none';
    }

    // Returns true if this node lives inside anything the user could still be typing/editing in:
    // a real <input>/<textarea>, a contenteditable region (checked via the ancestor-aware
    // isContentEditable property, not just the immediate parent), or an ARIA textbox/searchbox.
    function isInsideEditableContext(node) {
        const el = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
        if (!el) return false;

        // isContentEditable walks up the ancestor chain itself, so this catches text
        // nested several levels deep inside a contenteditable compose box (e.g. Slate/Draft.js editors).
        if (el.isContentEditable) return true;

        const editableAncestor = el.closest('input, textarea, [contenteditable], [contenteditable="true"], [role="textbox"], [role="searchbox"]');
        if (editableAncestor) return true;

        return false;
    }

    function convertTextNode(node) {
        const text = node.nodeValue;
        if (!text || !CIPHER_REGEX.test(text)) return;

        setTimeout(() => {
            const parent = node.parentNode;
            if (!parent) return;

            const tag = parent.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE') {
                return;
            }

            if (isInsideEditableContext(node)) return;

            if (parent.querySelector('.uaaa-btn-group')) return;

            CIPHER_REGEX.lastIndex = 0;
            const matches = text.match(CIPHER_REGEX);
            if (!matches) return;

            const cipherBlob = matches[0].replace(/\s/g, '').toUpperCase();

            const btnGroup = document.createElement('span');
            btnGroup.className = 'uaaa-btn-group';
            btnGroup.style.display = 'inline-flex';
            btnGroup.style.gap = '5px';
            btnGroup.style.marginLeft = '8px';
            btnGroup.style.verticalAlign = 'middle';

            const decBtn = document.createElement('button');
            decBtn.className = 'uaaa-action-dec';
            decBtn.innerText = '🔓 Decrypt';
            applyStyle(decBtn, '#7e5af0', '#000000', '#7e5af0');

            const infoBtn = document.createElement('a');
            infoBtn.className = 'uaaa-action-info';
            infoBtn.innerText = 'ℹ️ Site';
            infoBtn.href = `${ENCRYPTOR_URL}?m=dec&d=${encodeURIComponent(cipherBlob)}`;
            infoBtn.target = '_blank';
            infoBtn.rel = 'noopener noreferrer';
            applyStyle(infoBtn, '#00bfa5', '#000000', '#00bfa5');
            infoBtn.style.textDecoration = 'none';

            let decryptedCache = null;
            let isDecrypted = false;
            const originalTextValue = node.nodeValue;

            decBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();

                if (!isDecrypted) {
                    if (!decryptedCache) {
                        const myPrivateKey = GM_getValue('uaaa_my_private', '');
                        if (!myPrivateKey) {
                            alert('No private key set yet. Use the Tampermonkey menu → "Set My Private Key" first.');
                            return;
                        }
                        const passphrase = prompt('Passphrase for your private key:') || '';

                        decBtn.innerText = '⏳ ...';
                        try {
                            const { plaintext } = await UAAA.decrypt(cipherBlob, myPrivateKey, passphrase, null);
                            decryptedCache = plaintext;
                        } catch (err) {
                            console.error('UAAA decrypt error:', err);
                            alert('Decryption failed — wrong passphrase, wrong key, or not addressed to you.');
                            decBtn.innerText = '🔓 Decrypt';
                            applyStyle(decBtn, '#7e5af0', '#000000', '#7e5af0');
                            return;
                        }
                    }
                    if (decryptedCache) {
                        node.nodeValue = originalTextValue.replace(matches[0], decryptedCache);
                        decBtn.innerText = '🔒 Cipher';
                        applyStyle(decBtn, '#2ed573', '#000000', '#2ed573');
                        isDecrypted = true;
                    }
                } else {
                    node.nodeValue = originalTextValue;
                    decBtn.innerText = '🔓 Decrypt';
                    applyStyle(decBtn, '#7e5af0', '#000000', '#7e5af0');
                    isDecrypted = false;
                }
            });

            btnGroup.appendChild(decBtn);
            btnGroup.appendChild(infoBtn);

            if (node.nextSibling) {
                parent.insertBefore(btnGroup, node.nextSibling);
            } else {
                parent.appendChild(btnGroup);
            }
        }, 0);
    }

    function parseDOMTree(root) {
        if (!root) return;
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
        const textNodes = [];
        while (walker.nextNode()) {
            textNodes.push(walker.currentNode);
        }
        textNodes.forEach(convertTextNode);
    }

    parseDOMTree(document.body);

    const dynamicObserver = new MutationObserver((records) => {
        for (const record of records) {
            if (record.type === 'characterData') {
                convertTextNode(record.target);
            } else if (record.type === 'childList') {
                record.addedNodes.forEach(addedNode => {
                    if (addedNode.nodeType === Node.ELEMENT_NODE) {
                        parseDOMTree(addedNode);
                    } else if (addedNode.nodeType === Node.TEXT_NODE) {
                        convertTextNode(addedNode);
                    }
                });
            }
        }
    });

    dynamicObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
    });
})();
