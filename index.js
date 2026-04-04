// Chrome Cookie Decryption API v6.0 - Pure JS
console.log('API v6.0 initialized');

async function decryptV20Cookie(hex, key) {
    try {
        console.log('Decrypting v20 cookie...');
        const encrypted = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        const keyBytes = Uint8Array.from(atob(key), c => c.charCodeAt(0));
        
        // Parse v20: version(3) + nonce(12) + ciphertext + tag(16)
        const version = new TextDecoder().decode(encrypted.slice(0, 3));
        if (version !== 'v20') throw new Error('Invalid version: ' + version);
        
        const data = encrypted.slice(3);
        const nonce = data.slice(0, 12);
        const remaining = data.slice(12);
        const tag = remaining.slice(-16);
        const ciphertext = remaining.slice(0, -16);
        
        console.log(`Components: nonce=${nonce.length}, cipher=${ciphertext.length}, tag=${tag.length}`);
        
        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey,
            new Uint8Array([...ciphertext, ...tag])
        );
        
        const result = new TextDecoder().decode(decrypted);
        console.log('Decryption successful, length:', result.length);
        
        return { success: true, decrypted_value: result, message: 'OK' };
    } catch (e) {
        console.error('Decryption failed:', e);
        return { success: false, error: e.message };
    }
}

// Handle API calls
(async function() {
    const params = new URLSearchParams(location.search);
    const hex = params.get('hex');
    const key = params.get('key');
    
    if (hex && key) {
        const result = await decryptV20Cookie(hex, key);
        document.body.innerHTML = JSON.stringify(result);
        document.title = result.success ? 'SUCCESS' : 'FAILED';
        console.log('Result:', result);
    } else {
        const usage = {
            success: false,
            message: 'Usage: ?hex=HEXDATA&key=BASE64KEY',
            example: '?hex=763230...&key=abc123...'
        };
        document.body.innerHTML = JSON.stringify(usage);
        console.log('Usage info provided');
    }
})();
