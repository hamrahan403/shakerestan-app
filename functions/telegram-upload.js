// این تابع روی سرورهای Cloudflare اجرا می‌شود (نه در مرورگر کاربر)، پس توکن بات تلگرام
// هرگز برای کاربر قابل مشاهده نیست. توکن و chat_id را در تنظیمات Cloudflare Pages
// (Settings → Environment variables) با نام‌های TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID ذخیره کنید.
// آدرس این تابع پس از دیپلوی: https://<your-site>.pages.dev/telegram-upload

export async function onRequestPost(context) {
    const { request, env } = context;
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
