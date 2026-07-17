// ==UserScript==
// @name         UAAADecryptor
// @namespace    http://tampermonkey.net/
// @version      0.0.3
// @description  UAAAEncryption custom encryptor/decryptor
// @author       Matko802
// @match        *://*/*
// @require      https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/uaaa-core.js
// @grant        none
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    const ENCRYPTOR_URL = 'https://matko802.github.io/UAAAEncryption/';
    const CIPHER_REGEX = /(UAAA[UA]+)/gi;
    const CRYPTO_KEY = '\x55\x41\x41\x41'; // "UAAA"

    // Inject styles for better UI
    const styleSheet = document.createElement('style');
    styleSheet.textContent = `
        .uaaa-btn-group {
            display: inline-flex;
            gap: 6px;
            margin-left: 8px;
            vertical-align: middle;
        }
        .uaaa-btn {
            padding: 4px 8px;
            border-radius: 0;
            font-size: 0.75em;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            cursor: pointer;
            outline: none;
            user-select: none;
            border: 1px solid #cc3d4d;
            background: #000;
            color: #fff;
            transition: 0.2s;
        }
        .uaaa-btn:hover {
            background: #cc3d4d;
            color: #000;
        }
        .uaaa-btn-active {
            background: #cc3d4d;
            color: #000;
            border-color: #cc3d4d;
        }
        .uaaa-btn-success {
            background: #2ed573;
            color: #000;
            border-color: #2ed573;
        }
        .uaaa-btn-error {
            background: #ff3333;
            color: #fff;
            border-color: #ff3333;
        }
        .uaaa-link-btn {
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            border: 1px solid #505050;
            background: #000;
            color: #fff;
            padding: 4px 8px;
            font-size: 0.75em;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            transition: 0.2s;
        }
        .uaaa-link-btn:hover {
            background: #505050;
            color: #fff;
        }
    `;
    document.head.appendChild(styleSheet);

    function convertTextNode(node) {
        const text = node.nodeValue;
        if (!text || !CIPHER_REGEX.test(text)) return;

        setTimeout(() => {
            const parent = node.parentNode;
            if (!parent) return;

            const tag = parent.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'INPUT' || parent.contentEditable === 'true') {
                return;
            }

            if (parent.querySelector('.uaaa-btn-group')) return;

            CIPHER_REGEX.lastIndex = 0;
            const matches = text.match(CIPHER_REGEX);
            if (!matches) return;

            const cipherBlob = matches[0].replace(/\s/g, '').toUpperCase();

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

            decBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                if (!isDecrypted) {
                    if (!decryptedCache) {
                        try {
                            if (typeof _C !== 'function') {
                                decBtn.innerText = '⚠️';
                                decBtn.className = 'uaaa-btn uaaa-btn-error';
                                decBtn.title = 'Decryption engine failed to load';
                                console.error("UAAA API Error: _C function not loaded from GitHub.");
                                return;
                            }
                            decryptedCache = _C(cipherBlob, CRYPTO_KEY, false);
                        } catch (err) {
                            decBtn.innerText = '❌';
                            decBtn.className = 'uaaa-btn uaaa-btn-error';
                            decBtn.title = 'Invalid cipher text';
                            console.error("UAAA Decryption Error:", err.message);
                            return;
                        }
                    }
                    if (decryptedCache) {
                        node.nodeValue = originalTextValue.replace(matches[0], decryptedCache);
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

    let mutationTimeout;
    const dynamicObserver = new MutationObserver((records) => {
        // Debounce DOM updates to improve performance
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

    dynamicObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
    });
})();
