// ==UserScript==
// @name         UAAADecryptor
// @namespace    http://tampermonkey.net/
// @version      0.0.7
// @description  UAAAEncryption custom encryptor/decryptor (AES-GCM Edition)
// @author       Matko802
// @match        *://*/*
// @require      https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/uaaa-core.js
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    const ENCRYPTOR_URL = 'https://matko802.github.io/UAAAEncryption/';
    const CIPHER_REGEX = /UAAA[A-Za-z0-9+/]+={0,2}/g;
    const CRYPTO_KEY = '\x55\x41\x41\x41'; // "UAAA"

    function injectStyles() {
        if (document.getElementById('uaaa-styles')) return;
        const styleSheet = document.createElement('style');
        styleSheet.id = 'uaaa-styles';
        styleSheet.textContent = `
            .uaaa-btn-group { display: inline-flex; gap: 6px; margin-left: 8px; vertical-align: middle; }
            .uaaa-btn { padding: 4px 8px; border-radius: 0; font-size: 0.75em; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; outline: none; user-select: none; border: 1px solid #cc3d4d; background: #000; color: #fff; transition: 0.2s; }
            .uaaa-btn:hover { background: #cc3d4d; color: #000; }
            .uaaa-btn-active { background: #cc3d4d; color: #000; border-color: #cc3d4d; }
            .uaaa-btn-success { background: #2ed573; color: #000; border-color: #2ed573; }
            .uaaa-btn-error { background: #ff3333; color: #fff; border-color: #ff3333; }
            .uaaa-link-btn { text-decoration: none; display: inline-flex; align-items: center; border: 1px solid #505050; background: #000; color: #fff; padding: 4px 8px; font-size: 0.75em; font-family: 'Courier New', monospace; font-weight: bold; transition: 0.2s; }
            .uaaa-link-btn:hover { background: #505050; color: #fff; }
        `;
        (document.head || document.documentElement).appendChild(styleSheet);
    }

    function convertTextNode(node) {
        if (node._uaaaProcessed) return;

        const text = node.nodeValue;
        if (!text) return;

        CIPHER_REGEX.lastIndex = 0;
        if (!CIPHER_REGEX.test(text)) return;

        const parent = node.parentNode;
        if (!parent) return;

        const tag = parent.tagName;
        if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'INPUT' || parent.contentEditable === 'true') {
            return;
        }

        node._uaaaProcessed = true;

        CIPHER_REGEX.lastIndex = 0;
        const match = CIPHER_REGEX.exec(text);
        if (!match) return;

        const cipherBlob = match[0].replace(/\s/g, ''); 

        const btnGroup = document.createElement('span');
        btnGroup.className = 'uaaa-btn-group';

        const decBtn = document.createElement('button');
        decBtn.className = 'uaaa-btn';
        decBtn.innerText = '🔓';
        decBtn.title = 'Decrypt cipher text';

        const infoBtn = document.createElement('a');
        infoBtn.className = 'uaaa-link-btn';
        infoBtn.innerText = 'ℹ️';
        infoBtn.href = `${ENCRYPTOR_URL}?m=dec&d=${encodeURIComponent(cipherBlob)}`;
        infoBtn.target = '_blank';
        infoBtn.rel = 'noopener noreferrer';
        infoBtn.title = 'Open in UAAAEncryption';

        let decryptedCache = null;
        let isDecrypted = false;
        const originalTextValue = node.nodeValue;

        // Make the event listener asynchronous
        decBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();

            if (!isDecrypted) {
                if (!decryptedCache) {
                    try {
                        if (typeof _C !== 'function') {
                            decBtn.innerText = '⚠️';
                            decBtn.className = 'uaaa-btn uaaa-btn-error';
                            decBtn.title = 'Decryption engine failed to load';
                            return;
                        }
                        
                        decBtn.innerText = '⌛'; // Display loading state while awaiting Promise
                        
                        // Await the Web Crypto API result
                        decryptedCache = await _C(cipherBlob, CRYPTO_KEY, false);
                    } catch (err) {
                        decBtn.innerText = '❌';
                        decBtn.className = 'uaaa-btn uaaa-btn-error';
                        decBtn.title = err.message || 'Invalid cipher text';
                        return;
                    }
                }
                if (decryptedCache) {
                    node.nodeValue = originalTextValue.replace(match[0], decryptedCache);
                    decBtn.innerText = '✓';
                    decBtn.className = 'uaaa-btn uaaa-btn-success';
                    decBtn.title = 'Click to re-encrypt';
                    setTimeout(() => {
                        if (isDecrypted) {
                            decBtn.innerText = '🔒';
                            decBtn.className = 'uaaa-btn uaaa-btn-active';
                            decBtn.title = 'Re-encrypt to hide';
                        }
                    }, 1500);
                    isDecrypted = true;
                }
            } else {
                node.nodeValue = originalTextValue;
                decBtn.innerText = '🔓';
                decBtn.className = 'uaaa-btn';
                decBtn.title = 'Decrypt cipher text';
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
    }

    function parseDOMTree(root) {
        if (!root) return;
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
        const textNodes = [];
        while (walker.nextNode()) {
            textNodes.push(walker.currentNode);
        }
        textNodes.forEach(convertTextNode);
    }

    function init() {
        injectStyles();
        parseDOMTree(document.documentElement);

        let mutationTimeout;
        const dynamicObserver = new MutationObserver((records) => {
            clearTimeout(mutationTimeout);
            mutationTimeout = setTimeout(() => {
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
            }, 50);
        });

        dynamicObserver.observe(document.documentElement, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
