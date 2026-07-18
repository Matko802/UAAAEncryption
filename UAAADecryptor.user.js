// ==UserScript==
// @name         UAAADecryptor
// @namespace    http://tampermonkey.net/
// @version      0.0.8
// @description  UAAAEncryption custom encryptor/decryptor
// @author       Matko802
// @match        *://*/*
// @icon         https://github.com/Matko802/UAAAEncryption/blob/main/Assets/logo/UA.png?raw=true
// @require      https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/uaaa-core.js
// @updateURL    https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/UAAADecryptor.user.js
// @downloadURL  https://raw.githubusercontent.com/Matko802/UAAAEncryption/main/UAAADecryptor.user.js
// @homepageURL  https://github.com/Matko802/UAAAEncryption
// @grant        GM_registerMenuCommand
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-end
// ==/UserScript==

(function() {
    'use strict';

    // --- Persisted settings ---
    const MODE_KEY = 'uaaa_default_mode';

    let defaultMode = GM_getValue(MODE_KEY, 'encrypted');

    function toggleDefaultMode() {
        defaultMode = defaultMode === 'encrypted' ? 'decrypted' : 'encrypted';
        GM_setValue(MODE_KEY, defaultMode);
        registerMenu();
        reprocessAllExisting();
    }

    function registerMenu() {
        GM_registerMenuCommand(
            `UAAA: Default page mode -> ${defaultMode === 'encrypted' ? 'Encrypted' : 'Decrypted'}`,
            toggleDefaultMode
        );
    }
    registerMenu();

    // --- Configuration ---
    const CONFIG = {
        url: 'https://matko802.github.io/UAAAEncryption/',
        regex: /(UAAA[UA]+)/gi,
        key: '\x55\x41\x41\x41', // "UAAA"
        ignoreTags: new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'NOSCRIPT', 'CODE', 'PRE', 'CANVAS', 'SVG']),
        inputSelector: 'input[type="text"], input[type="search"], input[type="url"], input[type="tel"], input:not([type]), textarea, div[contenteditable="true"], [role="textbox"][contenteditable="true"]',
        inputIdleMs: 2000
    };

    const nodeQueue = new Set();
    let isProcessingQueue = false;
    const instances = new Set();

    // Tracks text mutations caused by our own script so we don't trigger infinite loops
    const ourInternalMutations = new WeakSet();

    // --- UI & Styling ---
    function injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            :root {
                --uaaa-bg: #000000;
                --uaaa-text: #ffffff;
                --uaaa-primary: #cc3d4d;
                --uaaa-success: #2ed573;
                --uaaa-error: #ff3333;
                --uaaa-border: #505050;
            }
            .uaaa-btn-group {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                margin: 0 6px;
                vertical-align: middle;
                user-select: none;
            }
            .uaaa-btn {
                padding: 2px 8px;
                border-radius: 0px;
                font-size: 0.75em;
                font-family: 'Courier New', Courier, monospace;
                font-weight: bold;
                cursor: pointer;
                outline: none;
                border: 1px solid var(--uaaa-primary);
                background: var(--uaaa-bg);
                color: var(--uaaa-text);
                transition: all 0.2s ease-in-out;
                text-decoration: none;
                line-height: 1.2;
            }
            .uaaa-btn:hover {
                background: var(--uaaa-primary);
                color: var(--uaaa-bg);
            }
            .uaaa-btn.success {
                border-color: var(--uaaa-success);
                background: var(--uaaa-success);
                color: var(--uaaa-bg);
            }
            .uaaa-btn.error {
                border-color: var(--uaaa-error);
                background: var(--uaaa-error);
                color: var(--uaaa-text);
            }
            .uaaa-btn.link {
                border-color: var(--uaaa-border);
            }
            .uaaa-btn.link:hover {
                background: var(--uaaa-border);
                color: var(--uaaa-text);
            }
            .uaaa-input-btn-group {
                position: absolute;
                display: none;
                align-items: center;
                gap: 4px;
                z-index: 999999;
                pointer-events: auto;
            }
            .uaaa-input-btn-group.visible {
                display: inline-flex;
            }
        `;
        document.head.appendChild(style);
    }

    function reprocessAllExisting() {
        for (const instance of instances) {
            instance.applyMode(defaultMode);
        }
    }

    // --- Core Processing Logic ---
    function processTextNode(node) {
        if (!node.nodeValue) return;

        const parent = node.parentNode;
        if (!parent || parent.isContentEditable || CONFIG.ignoreTags.has(parent.tagName)) {
            return;
        }

        if (!node.nodeValue.includes('UAAA')) {
            return;
        }

        CONFIG.regex.lastIndex = 0;
        const match = CONFIG.regex.exec(node.nodeValue);

        if (!match) return;

        // FIX: Clean up any old UAAA buttons in this bubble to prevent duplicates
        // when React rerenders or expands the text.
        const oldUIs = parent.querySelectorAll('.uaaa-message-ui');
        oldUIs.forEach(ui => ui.remove());

        const cipherText = match[0];
        const cipherBlob = cipherText.replace(/\s/g, '').toUpperCase();
        let decryptedCache = null;
        let isDecrypted = false;

        const container = document.createElement('span');
        container.className = 'uaaa-btn-group uaaa-message-ui';
        container.contentEditable = "false";

        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'uaaa-btn';
        toggleBtn.textContent = 'Decrypt';
        toggleBtn.title = 'Decrypt cipher text';

        const infoBtn = document.createElement('a');
        infoBtn.className = 'uaaa-btn link';
        infoBtn.textContent = 'Info';
        infoBtn.href = `${CONFIG.url}?m=dec&d=${encodeURIComponent(cipherBlob)}`;
        infoBtn.target = '_blank';
        infoBtn.rel = 'noopener noreferrer';
        infoBtn.title = 'Open in UAAAEncryption';

        container.appendChild(toggleBtn);
        container.appendChild(infoBtn);

        // FIX: Append to the parent container instead of splitting the text node
        parent.appendChild(container);

        function doDecrypt() {
            if (!decryptedCache) {
                try {
                    if (typeof _C !== 'function') throw new Error("Core API (_C) missing");
                    decryptedCache = _C(cipherBlob, CONFIG.key, false);
                } catch (err) {
                    toggleBtn.textContent = 'Error';
                    toggleBtn.className = 'uaaa-btn error';
                    toggleBtn.title = err.message;
                    return false;
                }
            }

            ourInternalMutations.add(node);
            // Seamlessly replace just the cipher string, leaving React's node intact
            node.nodeValue = node.nodeValue.replace(cipherText, decryptedCache);

            toggleBtn.textContent = 'Encrypt';
            toggleBtn.className = 'uaaa-btn success';
            toggleBtn.title = 'Re-encrypt text';
            isDecrypted = true;
            return true;
        }

        function doEncrypt() {
            ourInternalMutations.add(node);
            // Restore the exact cipher string
            if (decryptedCache) {
                node.nodeValue = node.nodeValue.replace(decryptedCache, cipherText);
            }

            toggleBtn.textContent = 'Decrypt';
            toggleBtn.className = 'uaaa-btn';
            toggleBtn.title = 'Decrypt cipher text';
            isDecrypted = false;
        }

        toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!isDecrypted) doDecrypt();
            else doEncrypt();
        });

        if (defaultMode === 'decrypted') {
            doDecrypt();
        }

        const instance = {
            get isDecrypted() { return isDecrypted; },
            applyMode(mode) {
                if (mode === 'decrypted' && !isDecrypted) doDecrypt();
                else if (mode === 'encrypted' && isDecrypted) doEncrypt();
            }
        };
        instances.add(instance);
    }

    // --- Performance Queuing ---
    function processQueue() {
        const startTime = performance.now();

        for (const node of nodeQueue) {
            if (performance.now() - startTime > 15) break;

            nodeQueue.delete(node);
            processTextNode(node);
        }

        if (nodeQueue.size > 0) {
            window.requestAnimationFrame(processQueue);
        } else {
            isProcessingQueue = false;
        }
    }

    function enqueueNode(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            nodeQueue.add(node);
        } else if (node.nodeType === Node.ELEMENT_NODE && !CONFIG.ignoreTags.has(node.tagName)) {
            const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, null, false);
            let currentNode;
            while ((currentNode = walker.nextNode())) {
                nodeQueue.add(currentNode);
            }
        }

        if (!isProcessingQueue && nodeQueue.size > 0) {
            isProcessingQueue = true;
            window.requestAnimationFrame(processQueue);
        }
    }

    // --- Encrypt-button-on-idle for form fields ---
    const inputStates = new WeakMap();

    function isEligibleInput(el) {
        if (!el) return false;
        if (el.matches && el.matches(CONFIG.inputSelector) && !el.readOnly && !el.disabled) return true;
        // Many chat apps (WhatsApp Web, Discord, Telegram Web, etc.) use a
        // contenteditable div as the compose box instead of a real <input>/<textarea>.
        if (el.isContentEditable) return true;
        return false;
    }

    // Reads the current text out of either a native form field or a contenteditable box.
    function getElText(el) {
        return el.isContentEditable ? el.innerText : el.value;
    }

    // Writes text back in a way that framework-controlled fields (React, etc.) actually notice.
    function setElText(el, text) {
        el.focus();
        if (el.isContentEditable) {
            const range = document.createRange();
            range.selectNodeContents(el);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            const inserted = document.execCommand && document.execCommand('insertText', false, text);
            if (!inserted) {
                el.textContent = text;
                el.dispatchEvent(new Event('input', { bubbles: true }));
            }
        } else {
            const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
            const nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value').set;
            nativeSetter.call(el, text);
            el.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }

    function getOrCreateState(el) {
        let state = inputStates.get(el);
        if (state) return state;

        const container = document.createElement('span');
        container.className = 'uaaa-btn-group uaaa-input-btn-group';
        container.contentEditable = "false";

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'uaaa-btn';
        btn.textContent = 'Encrypt';
        btn.title = 'Encrypt this field with UAAA';

        container.appendChild(btn);
        document.body.appendChild(container);

        state = { plaintext: '', isEncrypted: false, btnGroup: container, btn, timer: null, anchor: el };
        inputStates.set(el, state);

        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();

            if (!state.isEncrypted) {
                const plaintext = getElText(el);
                if (!plaintext) return;
                try {
                    if (typeof _C !== 'function') throw new Error("Core API (_C) missing");
                    const cipher = _C(plaintext, CONFIG.key, true);
                    state.plaintext = plaintext;
                    setElText(el, cipher);
                    state.isEncrypted = true;
                    btn.textContent = 'Decrypt';
                    btn.className = 'uaaa-btn success';
                    btn.title = 'Restore original text';
                } catch (err) {
                    btn.textContent = 'Error';
                    btn.className = 'uaaa-btn error';
                    console.error("[UAAA] Failed:", err.message);
                }
            } else {
                setElText(el, state.plaintext);
                state.isEncrypted = false;
                btn.textContent = 'Encrypt';
                btn.className = 'uaaa-btn';
            }
            el.focus();
        });

        return state;
    }

    function positionButton(state) {
        const el = state.anchor;
        if (!el || !document.body.contains(el)) return;

        const rect = el.getBoundingClientRect();
        const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
        const scrollY = window.pageYOffset || document.documentElement.scrollTop;

        state.btnGroup.style.visibility = 'hidden';
        state.btnGroup.classList.add('visible');
        state.btnGroup.style.display = 'inline-flex';
        const width = state.btnGroup.offsetWidth;
        const height = state.btnGroup.offsetHeight;

        const left = Math.min(rect.right + scrollX - width, rect.left + scrollX + 10);
        const top = Math.max(rect.top + scrollY - height - 6, scrollY + 6);

        state.btnGroup.style.left = `${Math.max(left, scrollX + 6)}px`;
        state.btnGroup.style.top = `${top}px`;
        state.btnGroup.style.visibility = 'visible';
    }

    function showButton(state, el) {
        if (!getElText(el)) {
            hideButton(state);
            return;
        }
        state.anchor = el;
        positionButton(state);
        state.btnGroup.classList.add('visible');
    }

    function hideButton(state) {
        state.btnGroup.classList.remove('visible');
        state.btnGroup.style.display = 'none';
    }

    document.addEventListener('input', (e) => {
        if (!isEligibleInput(e.target)) return;
        const el = e.target;
        const state = getOrCreateState(el);

        clearTimeout(state.timer);
        hideButton(state);

        if (state.isEncrypted) {
            state.isEncrypted = false;
            state.plaintext = '';
            state.btn.textContent = 'Encrypt';
            state.btn.className = 'uaaa-btn';
            state.btn.title = 'Encrypt this field with UAAA';
        }

        state.timer = setTimeout(() => showButton(state, el), CONFIG.inputIdleMs);
    }, true);

    document.addEventListener('focusin', (e) => {
        if (!isEligibleInput(e.target)) return;
        const el = e.target;
        const state = getOrCreateState(el);
        clearTimeout(state.timer);
        state.timer = setTimeout(() => showButton(state, el), CONFIG.inputIdleMs);
    }, true);

    document.addEventListener('focusout', (e) => {
        if (!isEligibleInput(e.target)) return;
        const state = inputStates.get(e.target);
        if (!state) return;
        clearTimeout(state.timer);
        hideButton(state);
    }, true);

    // --- Initialization & Observation ---
    injectStyles();
    enqueueNode(document.body);

    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.type === 'characterData') {
                const target = mutation.target;

                // 1. Ignore mutations caused by our script replacing the text
                if (ourInternalMutations.has(target)) {
                    ourInternalMutations.delete(target);
                    continue;
                }

                // 2. WhatsApp dynamically changed the text (e.g. user clicked Read More)
                // Queue the node to be reprocessed so the script can hook into the new text
                enqueueNode(target);

            } else if (mutation.type === 'childList') {
                for (const addedNode of mutation.addedNodes) {
                    enqueueNode(addedNode);
                }
            }
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
    });
})();
