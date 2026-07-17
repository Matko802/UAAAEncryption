// uaaa-core.js
function _C(t, k, e) {
    const _s = '\x55\x41\x41\x41'; 
    if (e) {
        let src = Array.from(t), dict = {}, _tc = [], phrase = src[0], code = 256;
        for (let i = 1; i < src.length; i++) {
            let c = src[i], p = phrase + c;
            if (dict[p] !== undefined) { phrase = p; } 
            else {
                _tc.push(phrase.length > 1 ? dict[phrase] : phrase.charCodeAt(0));
                if (code < 65535) dict[p] = code++;
                phrase = c;
            }
        }
        if (phrase) _tc.push(phrase.length > 1 ? dict[phrase] : phrase.charCodeAt(0));

        let b = [Math.floor(Math.random() * 65536)], c = b[0];
        for (let i = 0; i < _tc.length; i++) {
            let w = _tc[i] ^ ((k.charCodeAt(i % k.length) + c + i) % 65536);
            b.push(w); c = (c + w) % 65536;
        }

        let r = '';
        for (let v of b) {
            let p = v.toString(2).padStart(16, '0');
            for (let j of p) r += j === '0' ? '\x55' : '\x41';
        }
        return _s + r;
    } else {
        let x = t.replace(/[^UA]/gi, '').toUpperCase();
        if (!x.startsWith(_s)) throw new Error();
        let q = x.substring(_s.length);
        
        let rm = q.length % 16; 
        if (rm !== 0) q = q.substring(0, q.length - rm);
        if (!q) return '';

        let b = [];
        for (let i = 0; i < q.length; i += 16) 
            b.push(parseInt(q.substring(i, i + 16).replace(/U/g, '0').replace(/A/g, '1'), 2));
        
        let c = b[0], _dc = [];
        for (let i = 1; i < b.length; i++) {
            _dc.push(b[i] ^ ((k.charCodeAt((i - 1) % k.length) + c + (i - 1)) % 65536));
            c = (c + b[i]) % 65536;
        }
        if (_dc.length === 0) return '';

        let dict = {}, currChar = String.fromCharCode(_dc[0]), oldPhrase = currChar, out = [currChar], code = 256;
        for (let i = 1; i < _dc.length; i++) {
            let currCode = _dc[i], phrase;
            if (currCode < 256) { phrase = String.fromCharCode(currCode); } 
            else { phrase = dict[currCode] ? dict[currCode] : (oldPhrase + currChar); }
            out.push(phrase);
            currChar = phrase.charAt(0);
            if (code < 65535) dict[code++] = oldPhrase + currChar;
            oldPhrase = phrase;
        }
        return out.join('');
    }
}