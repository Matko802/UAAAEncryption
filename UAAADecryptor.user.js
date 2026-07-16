// ==UserScript==
// @name         UAAADecryptor
// @namespace    http://tampermonkey.net/
// @version      0.0.2
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

    // The _C() engine is no longer here. It is injected automatically by the @require tag above.

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

            decBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                if (!isDecrypted) {
                    if (!decryptedCache) {
                        try {
                            // Using the _C function loaded from your GitHub raw file
                            if (typeof _C === 'function') {
                                decryptedCache = _C(cipherBlob, CRYPTO_KEY, false);
                            } else {
                                console.error("UAAA API Error: _C function not loaded from GitHub.");
                            }
                        } catch (err) {
                            console.error("UAAA API Error:", err);
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
