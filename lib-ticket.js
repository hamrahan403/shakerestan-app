// امضا و بررسی توکن‌های کوتاه‌عمر (HMAC-SHA256) بدون نیاز به کتابخانه‌ی خارجی

function b64url(bytes) {
    let binary = '';
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecodeToStr(str) {
    const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const binary = atob(b64);
    return binary;
}

async function hmacKey(secret) {
    return crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
    );
}

// payload: object ساده (بدون تودرتوی پیچیده)؛ exp: زمان انقضا (ms epoch)
async function signTicket(secret, payload) {
    const body = JSON.stringify(payload);
    const encBody = b64url(new TextEncoder().encode(body));
    const key = await hmacKey(secret);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encBody));
    return `${encBody}.${b64url(sig)}`;
}

async function verifyTicket(secret, ticket) {
    if (!ticket || typeof ticket !== 'string' || !ticket.includes('.')) return null;
    const [encBody, encSig] = ticket.split('.');
    const key = await hmacKey(secret);
    const sigBytes = Uint8Array.from(b64urlDecodeToStr(encSig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(encBody));
    if (!valid) return null;
    try {
        const payload = JSON.parse(b64urlDecodeToStr(encBody));
        if (payload.exp && Date.now() > payload.exp) return null; // منقضی شده
        return payload;
    } catch (e) {
        return null;
    }
}

export { signTicket, verifyTicket };
