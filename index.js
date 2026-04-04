// Chrome Cookie Decryption API v6.1 - Updated for Chrome v80+
console.log('API v6.1 initialized - Chrome v80+ compatible');

// Modern Chrome v80+ AES-256-GCM decryption (v10 format)
async function decryptV10Cookie(hex, key) {
    try {
        console.log('Decrypting v10 (AES-256-GCM) cookie...');
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
        
        // Parse v10 format: version(3) + nonce(12) + ciphertext + tag(16)
        // Based on Chrome v80+ format from StackOverflow answer
        const version = new TextDecoder().decode(encrypted.slice(0, 3));
        console.log('Version detected:', version);
        
        if (version !== 'v10') {
            throw new Error('Invalid version for v10 decryption: ' + version);
        }
        
        // Chrome v80+ format: v10 + nonce(12) + ciphertext + tag(16)
        const data = encrypted.slice(3); // Skip 3-byte version
        const nonce = data.slice(0, 12); // 96-bit nonce
        const remaining = data.slice(12);
        const tag = remaining.slice(-16); // 128-bit tag
        const ciphertext = remaining.slice(0, -16);
        
        console.log('v10 Component lengths:', {
            nonce: nonce.length,
            ciphertext: ciphertext.length,
            tag: tag.length
        });
        
        if (nonce.length !== 12 || tag.length !== 16) {
            throw new Error(`Invalid v10 component lengths: nonce=${nonce.length}, tag=${tag.length}`);
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
        console.log('v10 Decryption successful, result length:', result.length);
        
        return {
            success: true,
            decrypted_value: result,
            message: 'v10 AES-256-GCM decryption successful',
            format: 'v10-aes-gcm'
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

// Legacy v20 decryption (existing function)
async function decryptV20Cookie(hex, key) {
    try {
        console.log('Decrypting v20 (legacy) cookie...');
        
        const encrypted = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        const keyBytes = Uint8Array.from(atob(key), c => c.charCodeAt(0));
        
        // Parse v20: version(3) + nonce(12) + ciphertext + tag(16)
        const version = new TextDecoder().decode(encrypted.slice(0, 3));
        
        if (version !== 'v20') {
            throw new Error('Invalid version for v20 decryption: ' + version);
        }
        
        const data = encrypted.slice(3);
        const nonce = data.slice(0, 12);
        const remaining = data.slice(12);
        const tag = remaining.slice(-16);
        const ciphertext = remaining.slice(0, -16);
        
        console.log('v20 Component lengths:', {
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
        console.log('v20 Decryption successful, result length:', result.length);
        
        return {
            success: true,
            decrypted_value: result,
            message: 'v20 legacy decryption successful',
            format: 'v20-legacy'
        };
    } catch (e) {
        console.error('v20 Decryption failed:', e.message);
        return {
            success: false,
            error: e.message,
            message: 'v20 decryption failed'
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
        if (format === 'v10-aes-gcm' || (format === 'auto' && hex.substring(0, 6) === '763130')) {
            result = await decryptV10Cookie(hex, key);
        } else if (format === 'v20-legacy' || (format === 'auto' && hex.substring(0, 6) === '763230')) {
            result = await decryptV20Cookie(hex, key);
        } else if (format === 'dpapi-direct') {
            result = {
                success: false,
                error: 'Direct DPAPI decryption not supported in browser',
                message: 'DPAPI requires Windows native tools'
            };
        } else {
            // Auto-detect by trying both methods
            console.log('Auto-detecting format...');
            result = await decryptV10Cookie(hex, key);
            if (!result.success) {
                console.log('v10 failed, trying v20...');
                result = await decryptV20Cookie(hex, key);
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
                'v10-aes-gcm': 'Modern Chrome v80+ AES-256-GCM',
                'v20-legacy': 'Legacy Chrome pre-v80',
                'dpapi-direct': 'Very old direct DPAPI (unsupported)',
                'auto': 'Auto-detect format (default)'
            },
            examples: {
                'v10': '?hex=763130...&key=abc123...&format=v10-aes-gcm',
                'v20': '?hex=763230...&key=abc123...&format=v20-legacy',
                'auto': '?hex=HEXDATA&key=BASE64KEY'
            }
        };
        
        document.body.innerHTML = JSON.stringify(usage, null, 2);
        document.title = 'USAGE';
        console.log('Usage info provided');
    }
})();
