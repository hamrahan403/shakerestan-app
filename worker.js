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
        let response;

        try {
            if (p === '/telegram-upload' && request.method === 'POST') response = await handleTelegramUpload(request, env);
            else if (p === '/telegram-file' && request.method === 'GET') response = await handleTelegramFileProxy(request, env);
            else if (p === '/api/auth/request-code' && request.method === 'POST') response = await handleRequestCode(request, env);
            else if (p === '/api/auth/verify-code' && request.method === 'POST') response = await handleVerifyCode(request, env);
            else if (p === '/api/auth/complete-login' && request.method === 'POST') response = await handleCompleteLogin(request, env);
            else if (p === '/api/auth/register' && request.method === 'POST') response = await handleRegister(request, env);
            else if (p === '/api/auth/login' && request.method === 'POST') response = await handleLogin(request, env);
            else if (p === '/api/auth/google/start' && request.method === 'GET') response = await handleGoogleStart(request, env);
            else if (p === '/api/auth/google/callback' && request.method === 'GET') response = await handleGoogleCallback(request, env);
            else if (p === '/api/auth/session-status' && request.method === 'POST') response = await handleSessionStatus(request, env);
            else if (p === '/api/fs' && request.method === 'POST') response = await handleFsProxy(request, env);
            else response = await env.ASSETS.fetch(request); // فایل‌های استاتیک (index.html و ...)
        } catch (e) {
            response = jsonRes({ error: e.message || 'خطای داخلی سرور' }, 500);
        }

        return addSecurityHeaders(response);
    }
};

// هدرهای امنیتی استاندارد روی همه‌ی پاسخ‌ها (چه صفحه‌ی اصلی، چه API)
function addSecurityHeaders(response) {
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Frame-Options', 'DENY'); // جلوگیری از قرار گرفتن سایت داخل iframe سایت‌های دیگر (Clickjacking)
    newHeaders.set('X-Content-Type-Options', 'nosniff'); // مرورگر نوع فایل رو حدس نزنه
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    newHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains'); // فقط HTTPS
    newHeaders.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=(self)');
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
    });
}

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

// ---------- رمزنگاری رمز عبور (PBKDF2 با Web Crypto، بومی Cloudflare Workers، بدون کتابخانه‌ی خارجی) ----------
async function hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const iterations = 100000;
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
    const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${iterations}:${saltHex}:${hashHex}`;
}
async function verifyPassword(password, stored) {
    if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
    const [iterStr, saltHex, hashHex] = stored.split(':');
    const iterations = parseInt(iterStr, 10);
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
    const computedHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (computedHex.length !== hashHex.length) return false;
    let diff = 0;
    for (let i = 0; i < computedHex.length; i++) diff |= computedHex.charCodeAt(i) ^ hashHex.charCodeAt(i);
    return diff === 0;
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

    const docId = safeId(emailLower);
    const existing = await firestoreGet(env, `authCodes/${docId}`);
    if (existing && existing.lockedUntilMs && Date.now() < existing.lockedUntilMs) {
        const minutesLeft = Math.ceil((existing.lockedUntilMs - Date.now()) / 60000);
        return jsonRes({ error: `تعداد تلاش‌های اشتباه زیاد بود؛ ${minutesLeft} دقیقه دیگر دوباره امتحان کنید` }, 429);
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    await firestoreSet(env, `authCodes/${docId}`, {
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
    const docId = safeId(emailLower);
    const stored = await firestoreGet(env, `authCodes/${docId}`);

    if (!stored) {
        return jsonRes({ error: 'کد اشتباه یا منقضی‌شده است' }, 400);
    }

    // قفل موقت بعد از تلاش‌های ناموفق زیاد (جلوگیری از حدس زدن خودکار کد)
    if (stored.lockedUntilMs && Date.now() < stored.lockedUntilMs) {
        const minutesLeft = Math.ceil((stored.lockedUntilMs - Date.now()) / 60000);
        return jsonRes({ error: `تعداد تلاش‌های اشتباه زیاد بود؛ ${minutesLeft} دقیقه دیگر دوباره امتحان کنید` }, 429);
    }

    if (stored.code !== String(code) || Date.now() > stored.expiresAtMs) {
        const attempts = (stored.attempts || 0) + 1;
        const update = { attempts };
        if (attempts >= 5) {
            update.lockedUntilMs = Date.now() + 15 * 60 * 1000; // ۱۵ دقیقه قفل
        }
        await firestoreUpdate(env, `authCodes/${docId}`, update);
        return jsonRes({ error: 'کد اشتباه یا منقضی‌شده است' }, 400);
    }
    await firestoreDelete(env, `authCodes/${docId}`);

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
// ثبت‌نام و ورود «کاربران عادی» (ایمیل + رمز عبور) — جایگزین ثبت‌نام تلفنی قدیمی
// همچنان نیاز به تایید دستی ادمین دارد (دقیقاً مثل روش قبلی).
// =====================================================================

async function handleRegister(request, env) {
    const { email, password, firstName, lastName, chatName, entryYear, major, avatarId } = await request.json();
    const emailLower = (email || '').trim().toLowerCase();
    if (!emailLower || !emailLower.includes('@')) return jsonRes({ error: 'ایمیل نامعتبر است' }, 400);
    if (!password || password.length < 6) return jsonRes({ error: 'رمز عبور باید حداقل ۶ کاراکتر باشد' }, 400);
    if (!firstName || !lastName || !chatName) return jsonRes({ error: 'نام، نام‌خانوادگی و نام نمایشی الزامی است' }, 400);

    const uid = 'u_' + (await sha256Hex(emailLower)).slice(0, 28);
    const existing = await firestoreGet(env, `users/${uid}`);
    if (existing && existing.passwordHash) return jsonRes({ error: 'این ایمیل قبلاً ثبت‌نام کرده است؛ از بخش ورود استفاده کنید' }, 400);

    const passwordHash = await hashPassword(password);
    await firestoreSet(env, `users/${uid}`, {
        email: emailLower, passwordHash, firstName, lastName, chatName,
        name: chatName, entryYear: entryYear || '', major: major || '',
        avatarId: avatarId || '', authType: 'password', status: 'pending',
        profileCompleted: true, createdAtMs: existing ? existing.createdAtMs : Date.now()
    });

    const session = await signTicket(env.WORKER_AUTH_SECRET, {
        uid, kind: 'password', email: emailLower, name: chatName,
        isPending: true, exp: Date.now() + SESSION_TTL_MS
    });
    return jsonRes({ session, uid, status: 'pending', name: chatName });
}

async function handleLogin(request, env) {
    const { email, password } = await request.json();
    const emailLower = (email || '').trim().toLowerCase();
    if (!emailLower || !password) return jsonRes({ error: 'ایمیل و رمز عبور را وارد کنید' }, 400);

    const uid = 'u_' + (await sha256Hex(emailLower)).slice(0, 28);
    const user = await firestoreGet(env, `users/${uid}`);
    if (!user || !user.passwordHash) return jsonRes({ error: 'حساب کاربری با این ایمیل یافت نشد' }, 400);

    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) return jsonRes({ error: 'رمز عبور اشتباه است' }, 400);

    if (user.status === 'rejected') return jsonRes({ error: 'عضویت شما توسط مدیر رد شده است' }, 403);

    const isPending = user.status !== 'approved';
    const isAdmin = emailLower === ADMIN_EMAIL;
    const editorId = isAdmin ? null : await findEditorByEmail(env, emailLower);
    const session = await signTicket(env.WORKER_AUTH_SECRET, {
        uid, kind: 'password', email: emailLower, name: user.chatName || user.name,
        isAdmin, editorId: editorId || null, isPending, exp: Date.now() + SESSION_TTL_MS
    });
    return jsonRes({ session, uid, status: isPending ? 'pending' : 'active', name: user.chatName || user.name, isAdmin, editorId: editorId || null });
}



// چک کردن اینکه آیا حساب کاربر عادی (ایمیل+رمزعبور) هنوز تایید نشده (با polling صدا زده می‌شود)
async function handleSessionStatus(request, env) {
    const session = await getSession(request, env);
    if (!session) return jsonRes({ error: 'نشست نامعتبر است' }, 401);

    if (session.kind === 'email' || session.kind === 'google') {
        const editorId = session.isAdmin ? null : await findEditorByEmail(env, session.email);
        const newSession = await signTicket(env.WORKER_AUTH_SECRET, {
            uid: session.uid, email: session.email, isAdmin: session.isAdmin, kind: session.kind,
            editorId: editorId || null, exp: Date.now() + SESSION_TTL_MS
        });
        return jsonRes({
            status: 'active', kind: session.kind, session: newSession,
            uid: session.uid, email: session.email, isAdmin: session.isAdmin, editorId: editorId || null
        });
    }

    // کاربر عادی (ایمیل+رمزعبور): وضعیت تاییدش را دوباره چک کن
    const user = await firestoreGet(env, `users/${session.uid}`);
    if (!user) return jsonRes({ status: 'pending', kind: 'password', uid: session.uid, name: session.name });

    if (user.status === 'rejected') {
        return jsonRes({ status: 'rejected', reason: user.rejectReason || '' });
    }
    if (user.status === 'approved') {
        const isAdmin = session.email === ADMIN_EMAIL;
        const editorId = isAdmin ? null : await findEditorByEmail(env, session.email);
        const newSession = await signTicket(env.WORKER_AUTH_SECRET, {
            uid: session.uid, kind: 'password', email: session.email, name: user.chatName || user.name,
            isAdmin, editorId: editorId || null, isPending: false, exp: Date.now() + SESSION_TTL_MS
        });
        return jsonRes({
            status: 'approved', session: newSession, kind: 'password',
            uid: session.uid, name: user.chatName || user.name, isAdmin, editorId: editorId || null
        });
    }
    return jsonRes({ status: 'pending', kind: 'password', uid: session.uid, name: user.chatName || user.name });
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
    const isBlockedGuest = !!(session && session.isPending); // کاربر عادیِ هنوز تاییدنشده

    // ---------- بخش چت کاملاً برای کاربران تاییدنشده قفل است ----------
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

    // پیام‌های تحویل کار: 'taskDeliveries/{taskId}/messages' — فقط فرستنده‌ی همون کار،
    // ویراستارِ گیرنده‌ی همون کار، یا ادمین اجازه‌ی خواندن/نوشتن دارند
    if (parts[0] === 'taskDeliveries' && parts.length > 1) {
        if (!session) return false;
        if (isAdmin) return true;
        const taskId = parts[1];
        const task = await firestoreGet(env, `tasks/${taskId}`);
        if (!task) return false;
        return session.uid === task.assignedTo || (session.editorId && session.editorId === task.deliveredToEditorId);
    }

    if (collection === 'users') {
        if (!session) return false;
        if (isAdmin) return true; // مدیر به همه‌ی کاربران دسترسی دارد (برای لیست کامل کاربران)
        // خواندن پروفایل هر کاربر واردشده‌ای آزاد است (برای نمایش پروفایل با کلیک روی نام در چت)
        if (op === 'get') return true;
        // نوشتن فقط روی سند خودِ کاربر
        if (op === 'set' || op === 'update') return docId === session.uid;
        return false;
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

    // به‌جای لینک مستقیم تلگرام (که مرورگر کاربر مستقیم بهش وصل می‌شد)، از پروکسی خودِ Worker استفاده می‌کنیم
    const secure_url = `/telegram-file?path=${encodeURIComponent(fileInfoJson.result.file_path)}`;
    return jsonRes({ secure_url, bytes: bytes.length, duration: result.video ? result.video.duration : undefined });
}

// نمایش فایل‌های آپلودشده از طریق خودِ Worker (نه لینک مستقیم api.telegram.org) —
// این‌طوری حتی اگر دامنه‌ی تلگرام برای کاربر فیلتر باشد، نمایش عکس/فیلم/صدا مشکلی پیدا نمی‌کند.
async function handleTelegramFileProxy(request, env) {
    const BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
    if (!BOT_TOKEN) return new Response('توکن بات تنظیم نشده', { status: 500 });

    const url = new URL(request.url);
    const path = url.searchParams.get('path');
    if (!path) return new Response('مسیر فایل مشخص نشده', { status: 400 });

    const tgRes = await fetch(`https://api.telegram.org/file/bot${BOT_TOKEN}/${path}`);
    if (!tgRes.ok) return new Response('دریافت فایل از تلگرام ناموفق بود', { status: 502 });

    const headers = new Headers();
    headers.set('Content-Type', tgRes.headers.get('Content-Type') || 'application/octet-stream');
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    return new Response(tgRes.body, { status: 200, headers });
}

// =====================================================================
// ورود با Google Sign-In (اختیاری، در کنار بقیه‌ی روش‌ها؛ هرگز جایگزین کامل نمی‌شود)
// =====================================================================

async function handleGoogleStart(request, env) {
    const url = new URL(request.url);
    const redirectUri = `${url.origin}/api/auth/google/callback`;
    const params = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'online',
        prompt: 'select_account'
    });
    return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`, 302);
}

async function handleGoogleCallback(request, env) {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    if (!code) return Response.redirect(`${url.origin}/?authError=google`, 302);

    const redirectUri = `${url.origin}/api/auth/google/callback`;
    try {
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
                redirect_uri: redirectUri, grant_type: 'authorization_code'
            })
        });
        const tokenJson = await tokenRes.json();
        if (!tokenRes.ok || !tokenJson.access_token) return Response.redirect(`${url.origin}/?authError=google`, 302);

        const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${tokenJson.access_token}` }
        });
        const userInfo = await userInfoRes.json();
        const emailLower = (userInfo.email || '').trim().toLowerCase();
        if (!emailLower) return Response.redirect(`${url.origin}/?authError=google`, 302);

        const uid = 'u_' + (await sha256Hex(emailLower)).slice(0, 28);
        const isAdmin = emailLower === ADMIN_EMAIL;
        const editorId = isAdmin ? null : await findEditorByEmail(env, emailLower);

        // اگر قبلاً با روش دیگری (رمز عبور) ثبت‌نام نکرده، یک پروفایل پایه با گوگل بساز (تایید خودکار)
        const existing = await firestoreGet(env, `users/${uid}`);
        if (!existing) {
            await firestoreSet(env, `users/${uid}`, {
                email: emailLower, name: userInfo.name || emailLower.split('@')[0],
                chatName: userInfo.name || emailLower.split('@')[0],
                avatarId: '', authType: 'google', status: 'approved',
                profileCompleted: false, createdAtMs: Date.now()
            });
        }

        const session = await signTicket(env.WORKER_AUTH_SECRET, {
            uid, email: emailLower, isAdmin, kind: 'google', editorId: editorId || null,
            exp: Date.now() + SESSION_TTL_MS
        });
        return Response.redirect(`${url.origin}/?googleSession=${encodeURIComponent(session)}`, 302);
    } catch (e) {
        return Response.redirect(`${url.origin}/?authError=google`, 302);
    }
}
