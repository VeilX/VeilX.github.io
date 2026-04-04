// Chrome Cookie Decryption API v6.2 - Updated for v12 format (Chrome v80+)
console.log('API v6.2 initialized - Chrome v80+ v12 format support');

// Chrome v80+ AES-256-GCM decryption (v12 format)
// Based on StackOverflow answer: https://stackoverflow.com/a/60611673
// Format: payload('v12') + nonce(12 bytes) + ciphertext + tag(16 bytes)
async function decryptV12Cookie(hex, key) {
    try {
        console.log('Decrypting v12 (Chrome v80+ AES-256-GCM) cookie...');
        console.log('Input hex length:', hex ? hex.length : 'undefined');
        console.log('Input key length:', key ? key.length : 'undefined');
        
        if (!hex || !key) {
            throw new Error('Missing hex or key parameter');
        }
        
        // Clean input
        hex = hex.replace(/[^a-fA-F0-9]/g, '');
        key = key.replace(/[^a-zA-Z0-9+/=]/g, '');
        
        const encrypted = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        const keyBytes = Uint8Array.from(atob(key), c => c.charCodeAt(0));
        
        console.log('Encrypted bytes length:', encrypted.length);
        console.log('Key bytes length:', keyBytes.length);
        
        // Parse v12 format: version(3) + nonce(12) + ciphertext + tag(16)
        // nonSecretPayloadLength = 3 for 'v12'
        const version = new TextDecoder().decode(encrypted.slice(0, 3));
        console.log('Version detected:', version);
        
        if (version !== 'v12') {
            throw new Error('Invalid version for v12 decryption: ' + version);
        }
        
        // Chrome v80+ v12 format: 'v12' + nonce(12) + ciphertext + tag(16)
        const data = encrypted.slice(3); // Skip 3-byte version ('v12')
        const nonce = data.slice(0, 12); // 96-bit nonce (12 bytes)
        const remaining = data.slice(12);
        const tag = remaining.slice(-16); // 128-bit tag (16 bytes)
        const ciphertext = remaining.slice(0, -16);
        
        console.log('v12 Component lengths:', {
            nonce: nonce.length,
            ciphertext: ciphertext.length,
            tag: tag.length
        });
        
        if (nonce.length !== 12 || tag.length !== 16) {
            throw new Error(`Invalid v12 component lengths: nonce=${nonce.length}, tag=${tag.length}`);
        }
        
        // Use Web Crypto API for AES-GCM (256-bit key, 96-bit IV, 128-bit tag)
        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: 128
            },
            cryptoKey,
            new Uint8Array([...ciphertext, ...tag])
        );
        
        const result = new TextDecoder().decode(decrypted);
        console.log('v12 Decryption successful, result length:', result.length);
        
        return {
            success: true,
            decrypted_value: result,
            message: 'v12 AES-256-GCM decryption successful',
            format: 'v12-aes-gcm'
        };
    } catch (e) {
        console.error('v12 Decryption failed:', e.message);
        return {
            success: false,
            error: e.message,
            message: 'v12 decryption failed'
        };
    }
}

// Legacy v10 decryption (compatibility)
async function decryptV10Cookie(hex, key) {
    try {
        console.log('Decrypting v10 (legacy) cookie...');
        
        const encrypted = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        const keyBytes = Uint8Array.from(atob(key), c => c.charCodeAt(0));
        
        // Parse v10: version(3) + nonce(12) + ciphertext + tag(16)
        const version = new TextDecoder().decode(encrypted.slice(0, 3));
        
        if (version !== 'v10') {
            throw new Error('Invalid version for v10 decryption: ' + version);
        }
        
        const data = encrypted.slice(3);
        const nonce = data.slice(0, 12);
        const remaining = data.slice(12);
        const tag = remaining.slice(-16);
        const ciphertext = remaining.slice(0, -16);
        
        console.log('v10 Component lengths:', {
            nonce: nonce.length,
            ciphertext: ciphertext.length,
            tag: tag.length
        });
        
        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey,
            new Uint8Array([...ciphertext, ...tag])
        );
        
        const result = new TextDecoder().decode(decrypted);
        console.log('v10 Decryption successful, result length:', result.length);
        
        return {
            success: true,
            decrypted_value: result,
            message: 'v10 legacy decryption successful',
            format: 'v10-legacy'
        };
    } catch (e) {
        console.error('v10 Decryption failed:', e.message);
        return {
            success: false,
            error: e.message,
            message: 'v10 decryption failed'
        };
    }
}

// Handle API calls via URL parameters
(async function() {
    console.log('Processing API request...');
    
    const params = new URLSearchParams(location.search);
    const hex = params.get('hex');
    const key = params.get('key');
    const format = params.get('format') || 'auto';
    
    console.log('URL parameters received:', {
        hex: hex ? `${hex.length} chars` : 'missing',
        key: key ? `${key.length} chars` : 'missing',
        format: format
    });
    
    if (hex && key) {
        let result;
        
        // Determine decryption method based on format or auto-detect
        if (format === 'v12-aes-gcm' || (format === 'auto' && hex.substring(0, 6) === '763132')) {
            // v12 = 0x76 0x31 0x32 = hex '763132'
            result = await decryptV12Cookie(hex, key);
        } else if (format === 'v10-legacy' || (format === 'auto' && hex.substring(0, 6) === '763130')) {
            // v10 = 0x76 0x31 0x30 = hex '763130' 
            result = await decryptV10Cookie(hex, key);
        } else if (format === 'dpapi-direct') {
            result = {
                success: false,
                error: 'Direct DPAPI decryption not supported in browser',
                message: 'DPAPI requires Windows native tools'
            };
        } else {
            // Auto-detect by trying both methods (v12 first for modern Chrome)
            console.log('Auto-detecting format...');
            result = await decryptV12Cookie(hex, key);
            if (!result.success) {
                console.log('v12 failed, trying v10...');
                result = await decryptV10Cookie(hex, key);
            }
            if (!result.success) {
                result.message = 'Auto-detection failed - unsupported format';
            }
        }
        
        // Set page content and title
        document.body.innerHTML = JSON.stringify(result, null, 2);
        document.title = result.success ? 'SUCCESS' : 'FAILED';
        
        console.log('Final result:', result);
        window.apiResult = result;
    } else {
        const usage = {
            success: false,
            error: 'Missing required parameters',
            message: 'Usage: ?hex=HEXDATA&key=BASE64KEY&format=FORMAT',
            formats: {
                'v12-aes-gcm': 'Modern Chrome v80+ AES-256-GCM (primary)',
                'v10-legacy': 'Legacy Chrome format',
                'dpapi-direct': 'Very old direct DPAPI (unsupported)',
                'auto': 'Auto-detect format (default)'
            },
            examples: {
                'v12': '?hex=763132...&key=abc123...&format=v12-aes-gcm',
                'v10': '?hex=763130...&key=abc123...&format=v10-legacy',
                'auto': '?hex=HEXDATA&key=BASE64KEY'
            },
            note: 'Chrome v80+ uses v12 format: payload("v12") + nonce(12) + ciphertext + tag(16)'
        };
        
        document.body.innerHTML = JSON.stringify(usage, null, 2);
        document.title = 'USAGE';
        console.log('Usage info provided');
    }
})();
