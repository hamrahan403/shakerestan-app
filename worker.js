// این فایل روی سرورهای Cloudflare اجرا می‌شود (نه در مرورگر کاربر)، پس توکن بات تلگرام
// هرگز برای کاربر قابل مشاهده نیست. توکن و chat_id را در تنظیمات پروژه
// (Settings → Variables and Secrets) با نام‌های TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID ذخیره کنید.

import { firestoreSet, firestoreGet, firestoreDelete } from './lib-firestore.js';
import { signTicket, verifyTicket } from './lib-ticket.js';

const ADMIN_EMAIL = 'hamrahanjozveh@gmail.com';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname === '/telegram-upload' && request.method === 'POST') {
            return handleTelegramUpload(request, env);
        }
        if (url.pathname === '/api/auth/request-code' && request.method === 'POST') {
            return handleRequestCode(request, env);
        }
        if (url.pathname === '/api/auth/verify-code' && request.method === 'POST') {
            return handleVerifyCode(request, env);
        }
        if (url.pathname === '/api/auth/bind-uid' && request.method === 'POST') {
            return handleBindUid(request, env);
        }

        // هر آدرس دیگری: فایل‌های استاتیک (index.html و ...) عادی سرو می‌شوند
        return env.ASSETS.fetch(request);
    }
};

function jsonRes(obj, status = 200) {
    return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

function firestoreDocIdFromEmail(email) {
    // ایمیل را برای استفاده به‌عنوان شناسه‌ی سند امن می‌کنیم (کاراکترهای غیرمجاز را جایگزین می‌کنیم)
    return email.toLowerCase().trim().replace(/[^a-z0-9@._-]/g, '_');
}

// مرحله‌ی ۱: ساخت کد ۶ رقمی، ذخیره در Firestore، ارسال با EmailJS
async function handleRequestCode(request, env) {
    try {
        console.log('DEBUG env keys:', Object.keys(env));
        console.log('DEBUG FIREBASE_CLIENT_EMAIL type:', typeof env.FIREBASE_CLIENT_EMAIL, JSON.stringify(env.FIREBASE_CLIENT_EMAIL));
        const { email } = await request.json();
        const emailLower = (email || '').trim().toLowerCase();
        if (!emailLower || !emailLower.includes('@')) {
            return jsonRes({ error: 'ایمیل نامعتبر است' }, 400);
        }

        const code = String(Math.floor(100000 + Math.random() * 900000));
        const docId = firestoreDocIdFromEmail(emailLower);
        await firestoreSet(env, `authCodes/${docId}`, {
            email: emailLower,
            code,
            createdAtMs: Date.now(),
            expiresAtMs: Date.now() + 10 * 60 * 1000 // ۱۰ دقیقه اعتبار
        });

        const emailRes = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                service_id: env.EMAILJS_SERVICE_ID,
                template_id: env.EMAILJS_TEMPLATE_ID,
                user_id: env.EMAILJS_PUBLIC_KEY,
                accessToken: env.EMAILJS_PRIVATE_KEY,
                template_params: { to_email: emailLower, code }
            })
        });
        if (!emailRes.ok) {
            const errText = await emailRes.text().catch(() => '');
            return jsonRes({ error: 'ارسال ایمیل ناموفق بود: ' + errText }, 502);
        }

        return jsonRes({ ok: true });
    } catch (e) {
        return jsonRes({ error: e.message || 'خطای داخلی' }, 500);
    }
}

// مرحله‌ی ۲: بررسی کد؛ در صورت درست بودن، یک «بلیط» کوتاه‌عمر برمی‌گرداند
async function handleVerifyCode(request, env) {
    try {
        const { email, code } = await request.json();
        const emailLower = (email || '').trim().toLowerCase();
        const docId = firestoreDocIdFromEmail(emailLower);
        const stored = await firestoreGet(env, `authCodes/${docId}`);

        if (!stored || stored.code !== String(code) || Date.now() > stored.expiresAtMs) {
            return jsonRes({ error: 'کد اشتباه یا منقضی‌شده است' }, 400);
        }

        await firestoreDelete(env, `authCodes/${docId}`);

        const ticket = await signTicket(env.WORKER_AUTH_SECRET, {
            email: emailLower,
            exp: Date.now() + 5 * 60 * 1000 // ۵ دقیقه برای تکمیل ورود
        });
        return jsonRes({ ticket });
    } catch (e) {
        return jsonRes({ error: e.message || 'خطای داخلی' }, 500);
    }
}

// مرحله‌ی ۳: بعد از اینکه کلاینت با signInAnonymously یک uid گرفت،
// این uid را به ایمیل تاییدشده متصل می‌کنیم (فقط Worker حق نوشتن این سند را دارد)
async function handleBindUid(request, env) {
    try {
        const { uid, ticket } = await request.json();
        if (!uid) return jsonRes({ error: 'uid ارسال نشده است' }, 400);

        const payload = await verifyTicket(env.WORKER_AUTH_SECRET, ticket);
        if (!payload || !payload.email) {
            return jsonRes({ error: 'بلیط نامعتبر یا منقضی‌شده است' }, 401);
        }

        const isAdmin = payload.email === ADMIN_EMAIL;
        await firestoreSet(env, `verifiedEmails/${uid}`, {
            email: payload.email,
            isAdmin,
            verifiedAtMs: Date.now()
        });

        return jsonRes({ email: payload.email, isAdmin });
    } catch (e) {
        return jsonRes({ error: e.message || 'خطای داخلی' }, 500);
    }
}

async function handleTelegramUpload(request, env) {
    const BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
    const CHAT_ID = env.TELEGRAM_CHAT_ID;

    if (!BOT_TOKEN || !CHAT_ID) {
        return new Response(JSON.stringify({ error: 'TELEGRAM_BOT_TOKEN یا TELEGRAM_CHAT_ID تنظیم نشده است' }), {
            status: 500, headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const { fileBase64, fileName, mimeType } = await request.json();
        if (!fileBase64) {
            return new Response(JSON.stringify({ error: 'فایلی ارسال نشده است' }), {
                status: 400, headers: { 'Content-Type': 'application/json' }
            });
        }

        // تبدیل base64 به بایت‌های خام
        const binary = atob(fileBase64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

        // محدودیت احتیاطی سمت سرور (علاوه بر بررسی سمت کاربر)
        if (bytes.length > 4.2 * 1024 * 1024) {
            return new Response(JSON.stringify({ error: 'حجم فایل بیش از حد مجاز است' }), {
                status: 413, headers: { 'Content-Type': 'application/json' }
            });
        }

        const mt = mimeType || 'application/octet-stream';
        const isImage = mt.startsWith('image/');
        const isVideo = mt.startsWith('video/');
        const endpoint = isImage ? 'sendPhoto' : isVideo ? 'sendVideo' : 'sendDocument';
        const fieldName = isImage ? 'photo' : isVideo ? 'video' : 'document';

        const form = new FormData();
        form.append('chat_id', CHAT_ID);
        form.append(fieldName, new Blob([bytes], { type: mt }), fileName || 'file');

        const sendRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${endpoint}`, {
            method: 'POST',
            body: form
        });
        const sendJson = await sendRes.json();
        if (!sendJson.ok) {
            return new Response(JSON.stringify({ error: sendJson.description || 'ارسال به تلگرام ناموفق بود' }), {
                status: 502, headers: { 'Content-Type': 'application/json' }
            });
        }

        const result = sendJson.result;
        const fileObj = result.document || result.video
            || (result.photo ? result.photo[result.photo.length - 1] : null);
        if (!fileObj || !fileObj.file_id) {
            return new Response(JSON.stringify({ error: 'پاسخ تلگرام قابل شناسایی نبود' }), {
                status: 502, headers: { 'Content-Type': 'application/json' }
            });
        }

        const fileInfoRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileObj.file_id}`);
        const fileInfoJson = await fileInfoRes.json();
        if (!fileInfoJson.ok) {
            return new Response(JSON.stringify({ error: 'دریافت مسیر فایل ناموفق بود' }), {
                status: 502, headers: { 'Content-Type': 'application/json' }
            });
        }

        const secure_url = `https://api.telegram.org/file/bot${BOT_TOKEN}/${fileInfoJson.result.file_path}`;

        return new Response(JSON.stringify({
            secure_url,
            bytes: bytes.length,
            duration: result.video ? result.video.duration : undefined
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
        return new Response(JSON.stringify({ error: e.message || 'خطای داخلی' }), {
            status: 500, headers: { 'Content-Type': 'application/json' }
        });
    }
}
