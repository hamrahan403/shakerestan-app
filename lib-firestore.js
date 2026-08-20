// کمک‌کننده‌های Google Service Account + Firestore REST برای اجرا در Cloudflare Workers
// (بدون نیاز به firebase-admin که در Workers قابل اجرا نیست)

function base64UrlEncode(bytes) {
    let binary = '';
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function strToUint8(str) {
    return new TextEncoder().encode(str);
}

function pemToArrayBuffer(pem) {
    const b64 = pem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s+/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

async function getGoogleAccessToken(env) {
    const privateKeyPem = (env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    const clientEmail = env.FIREBASE_CLIENT_EMAIL;
    if (!privateKeyPem || !clientEmail) {
        throw new Error('FIREBASE_PRIVATE_KEY یا FIREBASE_CLIENT_EMAIL تنظیم نشده است');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const claimSet = {
        iss: clientEmail,
        scope: 'https://www.googleapis.com/auth/datastore',
        aud: 'https://oauth2.googleapis.com/token',
        iat: now,
        exp: now + 3600
    };

    const encHeader = base64UrlEncode(strToUint8(JSON.stringify(header)));
    const encClaim = base64UrlEncode(strToUint8(JSON.stringify(claimSet)));
    const signingInput = `${encHeader}.${encClaim}`;

    const cryptoKey = await crypto.subtle.importKey(
        'pkcs8',
        pemToArrayBuffer(privateKeyPem),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, strToUint8(signingInput));
    const jwt = `${signingInput}.${base64UrlEncode(signature)}`;

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    const tokenJson = await tokenRes.json();
    if (!tokenJson.access_token) {
        throw new Error('دریافت access token گوگل ناموفق بود: ' + JSON.stringify(tokenJson));
    }
    return tokenJson.access_token;
}

// تبدیل مقدار جاوااسکریپت ساده به فرمت typed مورد نیاز Firestore REST API
function toFirestoreValue(v) {
    if (v === null || v === undefined) return { nullValue: null };
    if (typeof v === 'string') return { stringValue: v };
    if (typeof v === 'boolean') return { booleanValue: v };
    if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
    if (Array.isArray(v)) return { arrayValue: { values: v.map(toFirestoreValue) } };
    if (typeof v === 'object') return { mapValue: { fields: toFirestoreFields(v) } };
    return { stringValue: String(v) };
}

function toFirestoreFields(obj) {
    const fields = {};
    for (const k of Object.keys(obj || {})) fields[k] = toFirestoreValue(obj[k]);
    return fields;
}

function fromFirestoreValue(v) {
    if (!v) return null;
    if ('stringValue' in v) return v.stringValue;
    if ('booleanValue' in v) return v.booleanValue;
    if ('integerValue' in v) return parseInt(v.integerValue, 10);
    if ('doubleValue' in v) return v.doubleValue;
    if ('nullValue' in v) return null;
    if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromFirestoreValue);
    if ('mapValue' in v) return fromFirestoreFields(v.mapValue.fields || {});
    return null;
}

function fromFirestoreFields(fields) {
    const obj = {};
    for (const k of Object.keys(fields || {})) obj[k] = fromFirestoreValue(fields[k]);
    return obj;
}

// نوشتن/ادغام یک سند (create/merge). path مثل 'authCodes/some%40email.com'
async function firestoreSet(env, path, data) {
    const token = await getGoogleAccessToken(env);
    const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
    const res = await fetch(url, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: toFirestoreFields(data) })
    });
    const json = await res.json();
    if (!res.ok) throw new Error('Firestore set ناموفق بود: ' + JSON.stringify(json));
    return json;
}

async function firestoreGet(env, path) {
    const token = await getGoogleAccessToken(env);
    const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
    const res = await fetch(url, { headers: { 'Authorization': `Bearer ${token}` } });
    if (res.status === 404) return null;
    const json = await res.json();
    if (!res.ok) throw new Error('Firestore get ناموفق بود: ' + JSON.stringify(json));
    return fromFirestoreFields(json.fields || {});
}

async function firestoreDelete(env, path) {
    const token = await getGoogleAccessToken(env);
    const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
    await fetch(url, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
}

export { getGoogleAccessToken, firestoreSet, firestoreGet, firestoreDelete, toFirestoreFields, fromFirestoreFields };
