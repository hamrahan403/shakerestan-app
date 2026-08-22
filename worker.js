// این فایل روی سرورهای Cloudflare اجرا می‌شود (نه در مرورگر کاربر)، پس هیچ‌کدام از این توکن‌ها
// (تلگرام، فایربیس، ایمیل‌جی‌اس) هرگز برای کاربر قابل مشاهده نیست. همه در
// Settings → Variables and Secrets پروژه‌ی Cloudflare ذخیره می‌شوند.
//
// این نسخه دیگر هیچ تماس مستقیمی بین مرورگر کاربر و سرورهای Google/Firebase انجام نمی‌دهد
// (چون بعضی کاربران از ایران بدون فیلترشکن به identitytoolkit.googleapis.com دسترسی نداشتند).
// به‌جایش: ورود با «کد ۶ رقمی ایمیل» یا «ثبت‌نام تلفنی»، و تمام عملیات نوشتن/خواندنِ محافظت‌شده
// روی Firestore، از طریق همین Worker (با Service Account) انجام می‌شود.

import { firestoreSet, firestoreGet, firestoreDelete, firestoreAdd, firestoreUpdate, firestoreList } from './lib-firestore.js';
import { signTicket, verifyTicket } from './lib-ticket.js';

const ADMIN_EMAIL = 'hamrahanjozveh@gmail.com';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // ۳۰ روز

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const p = url.pathname;

        try {
            if (p === '/telegram-upload' && request.method === 'POST') return await handleTelegramUpload(request, env);
            if (p === '/api/auth/request-code' && request.method === 'POST') return await handleRequestCode(request, env);
            if (p === '/api/auth/verify-code' && request.method === 'POST') return await handleVerifyCode(request, env);
            if (p === '/api/auth/complete-login' && request.method === 'POST') return await handleCompleteLogin(request, env);
            if (p === '/api/auth/phone-signup' && request.method === 'POST') return await handlePhoneSignup(request, env);
            if (p === '/api/auth/session-status' && request.method === 'POST') return await handleSessionStatus(request, env);
            if (p === '/api/fs' && request.method === 'POST') return await handleFsProxy(request, env);
        } catch (e) {
            return jsonRes({ error: e.message || 'خطای داخلی سرور' }, 500);
        }

        // هر آدرس دیگری: فایل‌های استاتیک (index.html و ...) عادی سرو می‌شوند
        return env.ASSETS.fetch(request);
    }
};

function jsonRes(obj, status = 200) {
    return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

function safeId(str) {
    return String(str).toLowerCase().trim().replace(/[^a-z0-9@._-]/g, '_');
}

async function sha256Hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSession(request, env) {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return null;
    return await verifyTicket(env.WORKER_AUTH_SECRET, token);
}

// =====================================================================
// ورود ایمیلی: کد ۶ رقمی
// =====================================================================

async function handleRequestCode(request, env) {
    const { email } = await request.json();
    const emailLower = (email || '').trim().toLowerCase();
    if (!emailLower || !emailLower.includes('@')) return jsonRes({ error: 'ایمیل نامعتبر است' }, 400);

    const code = String(Math.floor(100000 + Math.random() * 900000));
    await firestoreSet(env, `authCodes/${safeId(emailLower)}`, {
        email: emailLower, code,
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 10 * 60 * 1000
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
}

async function handleVerifyCode(request, env) {
    const { email, code } = await request.json();
    const emailLower = (email || '').trim().toLowerCase();
    const stored = await firestoreGet(env, `authCodes/${safeId(emailLower)}`);

    if (!stored || stored.code !== String(code) || Date.now() > stored.expiresAtMs) {
        return jsonRes({ error: 'کد اشتباه یا منقضی‌شده است' }, 400);
    }
    await firestoreDelete(env, `authCodes/${safeId(emailLower)}`);

    const ticket = await signTicket(env.WORKER_AUTH_SECRET, {
        email: emailLower,
        exp: Date.now() + 5 * 60 * 1000
    });
    return jsonRes({ ticket });
}

// مرحله‌ی نهایی ورود ایمیلی: uid را خودِ Worker می‌سازد (دیگر نیازی به signInAnonymously نیست)
// و یک «توکن نشست» طولانی‌مدت برمی‌گرداند که از این پس هویت کاربر در همه‌ی درخواست‌هاست.
async function findEditorByEmail(env, email) {
    try {
        const editors = await firestoreList(env, 'editors', {});
        const match = editors.find(ed => (ed.email || '').toLowerCase() === email.toLowerCase());
        return match ? match.id : null;
    } catch (e) {
        return null;
    }
}

async function handleCompleteLogin(request, env) {
    const { ticket } = await request.json();
    const payload = await verifyTicket(env.WORKER_AUTH_SECRET, ticket);
    if (!payload || !payload.email) return jsonRes({ error: 'بلیط نامعتبر یا منقضی‌شده است' }, 401);

    const uid = 'u_' + (await sha256Hex(payload.email)).slice(0, 28);
    const isAdmin = payload.email === ADMIN_EMAIL;
    const editorId = isAdmin ? null : await findEditorByEmail(env, payload.email);

    await firestoreSet(env, `verifiedEmails/${uid}`, { email: payload.email, isAdmin, verifiedAtMs: Date.now() });

    const session = await signTicket(env.WORKER_AUTH_SECRET, {
        uid, email: payload.email, isAdmin, kind: 'email', editorId: editorId || null,
        exp: Date.now() + SESSION_TTL_MS
    });
    return jsonRes({ session, uid, email: payload.email, isAdmin, editorId: editorId || null });
}

// =====================================================================
// ثبت‌نام تلفنی/مهمان (جایگزین signInAnonymously + نوشتن مستقیم pendingRequests)
// =====================================================================

async function handlePhoneSignup(request, env) {
    const { firstName, lastName, phone } = await request.json();
    if (!firstName || !lastName || !phone) return jsonRes({ error: 'همه فیلدها الزامی است' }, 400);

    const uid = 'u_' + (await sha256Hex('phone:' + phone.trim())).slice(0, 28);
    const reqId = uid; // شناسه‌ی درخواست را همان uid می‌گذاریم تا جستجو ساده بماند

    const existing = await firestoreGet(env, `pendingRequests/${reqId}`);
    if (existing && existing.status === 'approved') {
        const session = await signTicket(env.WORKER_AUTH_SECRET, {
            uid, kind: 'phone', name: `${existing.firstName} ${existing.lastName}`, phone: existing.phone,
            isGuest: false, pendingId: null, exp: Date.now() + SESSION_TTL_MS
        });
        return jsonRes({ session, uid, isGuest: false, name: `${existing.firstName} ${existing.lastName}`, phone: existing.phone });
    }

    await firestoreSet(env, `pendingRequests/${reqId}`, {
        uid, firstName, lastName, phone,
        status: 'pending', approved: false,
        createdAtMs: existing ? existing.createdAtMs : Date.now()
    });

    const session = await signTicket(env.WORKER_AUTH_SECRET, {
        uid, kind: 'phone', name: `${firstName} ${lastName}`, phone,
        isGuest: true, pendingId: reqId, exp: Date.now() + SESSION_TTL_MS
    });
    return jsonRes({ session, uid, isGuest: true, pendingId: reqId, name: `${firstName} ${lastName}`, phone });
}

// چک کردن اینکه آیا درخواست تلفنی تایید/رد شده (جایگزین onSnapshot زنده - با polling صدا زده می‌شود)
async function handleSessionStatus(request, env) {
    const session = await getSession(request, env);
    if (!session) return jsonRes({ error: 'نشست نامعتبر است' }, 401);

    if (session.kind === 'email') {
        const editorId = session.isAdmin ? null : await findEditorByEmail(env, session.email);
        const newSession = await signTicket(env.WORKER_AUTH_SECRET, {
            uid: session.uid, email: session.email, isAdmin: session.isAdmin, kind: 'email',
            editorId: editorId || null, exp: Date.now() + SESSION_TTL_MS
        });
        return jsonRes({
            status: 'active', kind: 'email', session: newSession,
            uid: session.uid, email: session.email, isAdmin: session.isAdmin, editorId: editorId || null
        });
    }

    // کاربر تلفنی: وضعیت تاییدش را دوباره چک کن
    const data = await firestoreGet(env, `pendingRequests/${session.pendingId || session.uid}`);
    if (!data) {
        return jsonRes({
            status: session.isGuest ? 'pending' : 'active', kind: 'phone',
            uid: session.uid, name: session.name, phone: session.phone,
            pendingId: session.pendingId || null
        });
    }

    if (data.status === 'rejected') {
        return jsonRes({ status: 'rejected', reason: data.rejectReason || '' });
    }
    if (data.status === 'approved' || data.approved) {
        const newSession = await signTicket(env.WORKER_AUTH_SECRET, {
            uid: session.uid, kind: 'phone', name: session.name, phone: session.phone,
            isGuest: false, pendingId: null, exp: Date.now() + SESSION_TTL_MS
        });
        return jsonRes({
            status: 'approved', session: newSession, kind: 'phone',
            uid: session.uid, name: session.name, phone: session.phone, pendingId: null
        });
    }
    return jsonRes({
        status: 'pending', kind: 'phone',
        uid: session.uid, name: session.name, phone: session.phone, pendingId: session.pendingId
    });
}

// =====================================================================
// پروکسی عمومی Firestore — تمام خواندن/نوشتنِ محافظت‌شده از این مسیر عبور می‌کند.
// مجوزها اینجا دستی و مشابه firestore rules قبلی بررسی می‌شوند.
// =====================================================================

async function isTaskAssignee(env, uid) {
    const doc = await firestoreGet(env, `taskAssignees/${uid}`);
    return !!doc;
}

// کالکشن‌هایی که فقط ادمین حق نوشتن روشون رو داره (بیشتر محتوای اپ)
const ADMIN_ONLY_WRITE_COLLECTIONS = new Set([
    'notes', 'videos', 'subjects', 'announcements', 'collabCalls', 'editors', 'taskAssignees'
]);

async function checkFsPermission(env, session, op, collection, docId) {
    const isAdmin = !!(session && session.isAdmin);
    const isBlockedGuest = !!(session && session.isGuest); // کاربر تلفنی که هنوز تایید نشده

    // ---------- بخش چت کاملاً برای مهمان/تلفنیِ تاییدنشده قفل است ----------
    const CHAT_COLLECTIONS = ['publicChat', 'anonChat', 'adminChat', 'editors'];
    if (CHAT_COLLECTIONS.includes(String(collection).split('/')[0]) && isBlockedGuest) {
        return false;
    }

    const parts = String(collection).split('/').filter(Boolean);

    // ---------- چت عمومی: خواندن برای همه آزاد، ارسال برای کاربر واردشده، حذف فقط ادمین ----------
    if (parts[0] === 'publicChat') {
        if (op === 'list' || op === 'get') return true;
        if (op === 'delete') return isAdmin;
        return !!session;
    }

    // ---------- چت ناشناس / چت مدیر ----------
    // 'anonChat' یا 'adminChat' (بدون ادامه، docId = uid خود کاربر): فقط خودِ همون کاربر یا ادمین
    // 'anonChat/{uid}/messages': فقط خودِ همون کاربر یا ادمین
    if (parts[0] === 'anonChat' || parts[0] === 'adminChat') {
        if (parts.length === 1) {
            if (op === 'list') return isAdmin;
            if (!session) return false;
            // set/update روی خودِ سند ترد: docId باید uid خودِ کاربر باشد (یا ادمین)
            return isAdmin || (docId && session.uid === docId);
        }
        if (!session) return false;
        const threadUid = parts[1]; // .../{uid}/messages
        return isAdmin || session.uid === threadUid;
    }

    // ---------- چت ویراستاران ----------
    // 'editors' (بدون ادامه): پروفایل ویراستاران، از قبل توسط ADMIN_ONLY_WRITE_COLLECTIONS پوشش داده می‌شه
    // 'editors/{editorId}/threads' (docId = uid کاربر عادی): خودِ همون کاربر، خودِ ویراستار مربوطه، یا ادمین
    // 'editors/{editorId}/threads/{uid}/messages': همان‌طور
    if (parts[0] === 'editors' && parts.length > 1) {
        if (!session) return false;
        if (isAdmin) return true;
        if (session.editorId && session.editorId === parts[1]) return true;
        if (parts.length >= 4) {
            const threadUid = parts[3]; // .../threads/{uid}/messages
            return session.uid === threadUid;
        }
        if (parts.length === 3 && parts[2] === 'threads') {
            // ست/آپدیت روی سطح خودِ ترد: docId باید uid خودِ کاربر باشد
            return !!(docId && session.uid === docId);
        }
        return false;
    }

    if (ADMIN_ONLY_WRITE_COLLECTIONS.has(collection)) {
        if (op === 'get' || op === 'list') return true; // خواندن برای همه آزاد
        return isAdmin; // نوشتن/حذف فقط ادمین
    }

    if (collection === 'tasks') {
        if (!session) return false;
        if (op === 'list' || op === 'get') return isAdmin || await isTaskAssignee(env, session.uid);
        if (op === 'add') return isAdmin;
        if (op === 'update') return isAdmin || await isTaskAssignee(env, session.uid);
        return isAdmin;
    }

    if (collection === 'users') {
        if (!session) return false;
        // هر کاربر واردشده‌ای فقط می‌تونه سند خودش رو بخونه/بنویسه
        if (op === 'get' || op === 'set' || op === 'update') return docId === session.uid;
        return isAdmin;
    }

    if (collection === 'pendingRequests') {
        return isAdmin; // فقط ادمین برای تایید/رد
    }

    if (collection === 'settings') {
        if (op === 'get' || op === 'list') return true; // خواندن (مثلاً آواتار انتخابی مدیر) برای همه آزاد
        return isAdmin; // نوشتن فقط ادمین
    }

    // پیش‌فرض محتاطانه: نیاز به نشست معتبر
    return !!session;
}

async function handleFsProxy(request, env) {
    const session = await getSession(request, env);
    const { op, collection, docId, data, orderByField, orderByDir } = await request.json();
    if (!collection) return jsonRes({ error: 'collection مشخص نشده' }, 400);

    const allowed = await checkFsPermission(env, session, op, collection, docId);
    if (!allowed) return jsonRes({ error: 'دسترسی غیرمجاز' }, 403);

    try {
        if (op === 'list') {
            const items = await firestoreList(env, collection, { orderByField, orderByDir });
            return jsonRes({ items });
        }
        if (op === 'get') {
            if (!docId) return jsonRes({ error: 'docId لازم است' }, 400);
            const item = await firestoreGet(env, `${collection}/${docId}`);
            return jsonRes({ item });
        }
        if (op === 'set') {
            if (!docId) return jsonRes({ error: 'docId لازم است' }, 400);
            await firestoreSet(env, `${collection}/${docId}`, data || {});
            return jsonRes({ ok: true });
        }
        if (op === 'update') {
            if (!docId) return jsonRes({ error: 'docId لازم است' }, 400);
            await firestoreUpdate(env, `${collection}/${docId}`, data || {});
            return jsonRes({ ok: true });
        }
        if (op === 'delete') {
            if (!docId) return jsonRes({ error: 'docId لازم است' }, 400);
            await firestoreDelete(env, `${collection}/${docId}`);
            return jsonRes({ ok: true });
        }
        if (op === 'add') {
            const result = await firestoreAdd(env, collection, data || {});
            return jsonRes({ item: result });
        }
        if (op === 'findByEmail') {
            // معادل ساده‌ی where('email','==', email) — چون UID کاربران از sha256(email) ساخته می‌شه،
            // به‌جای جستجوی واقعی، مستقیم UID رو حساب می‌کنیم و همون سند رو می‌خونیم.
            const email = String((data && data.email) || '').trim().toLowerCase();
            if (!email) return jsonRes({ error: 'email لازم است' }, 400);
            const uid = 'u_' + (await sha256Hex(email)).slice(0, 28);
            const item = await firestoreGet(env, `${collection}/${uid}`);
            return jsonRes({ item: item ? { ...item, id: uid } : null });
        }
        return jsonRes({ error: 'op نامعتبر است' }, 400);
    } catch (e) {
        return jsonRes({ error: e.message || 'خطای Firestore' }, 500);
    }
}

// =====================================================================
// آپلود جزوه/عکس/فیلم به تلگرام (بدون تغییر نسبت به قبل)
// =====================================================================

async function handleTelegramUpload(request, env) {
    const BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
    const CHAT_ID = env.TELEGRAM_CHAT_ID;
    if (!BOT_TOKEN || !CHAT_ID) return jsonRes({ error: 'TELEGRAM_BOT_TOKEN یا TELEGRAM_CHAT_ID تنظیم نشده است' }, 500);

    const { fileBase64, fileName, mimeType } = await request.json();
    if (!fileBase64) return jsonRes({ error: 'فایلی ارسال نشده است' }, 400);

    const binary = atob(fileBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    if (bytes.length > 4.2 * 1024 * 1024) return jsonRes({ error: 'حجم فایل بیش از حد مجاز است' }, 413);

    const mt = mimeType || 'application/octet-stream';
    const isImage = mt.startsWith('image/');
    const isVideo = mt.startsWith('video/');
    const endpoint = isImage ? 'sendPhoto' : isVideo ? 'sendVideo' : 'sendDocument';
    const fieldName = isImage ? 'photo' : isVideo ? 'video' : 'document';

    const form = new FormData();
    form.append('chat_id', CHAT_ID);
    form.append(fieldName, new Blob([bytes], { type: mt }), fileName || 'file');

    const sendRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${endpoint}`, { method: 'POST', body: form });
    const sendJson = await sendRes.json();
    if (!sendJson.ok) return jsonRes({ error: sendJson.description || 'ارسال به تلگرام ناموفق بود' }, 502);

    const result = sendJson.result;
    const fileObj = result.document || result.video || (result.photo ? result.photo[result.photo.length - 1] : null);
    if (!fileObj || !fileObj.file_id) return jsonRes({ error: 'پاسخ تلگرام قابل شناسایی نبود' }, 502);

    const fileInfoRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileObj.file_id}`);
    const fileInfoJson = await fileInfoRes.json();
    if (!fileInfoJson.ok) return jsonRes({ error: 'دریافت مسیر فایل ناموفق بود' }, 502);

    const secure_url = `https://api.telegram.org/file/bot${BOT_TOKEN}/${fileInfoJson.result.file_path}`;
    return jsonRes({ secure_url, bytes: bytes.length, duration: result.video ? result.video.duration : undefined });
}
