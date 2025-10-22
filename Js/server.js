const http = require('http');
const crypto = require('crypto');
const querystring = require('querystring');
const fs = require('fs');

// مرحله 1: خواندن توکن از فایل
const token = fs.readFileSync('../token.txt', 'utf8').trim();

const server = http.createServer((req, res) => {
    // تنظیم هدرهای CORS
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // مدیریت درخواست OPTIONS
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // فقط POST requests را پردازش کن
    if (req.method !== 'POST') {
        res.writeHead(405);
        res.end(JSON.stringify({
            status: 'error',
            message: 'Method not allowed'
        }));
        return;
    }

    let body = '';

    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        try {
            const data = JSON.parse(body);

            // بررسی وجود initData
            if (!data.initData) {
                res.writeHead(400);
                res.end(JSON.stringify({
                    status: 'error',
                    message: 'داده‌ای دریافت نشد'
                }));
                return;
            }

            const initDataString = data.initData;

            // مرحله 1: تجزیه رشته initData به یک آرایه از رشته‌ها و جداسازی hash
            const webAppData = querystring.parse(initDataString);
            const receivedHash = webAppData.hash || '';
            delete webAppData.hash;

            // مرحله 2: مرتب‌سازی کلیدها به ترتیب الفبایی و ایجاد رشته داده
            const keyValues = [];
            for (const key in webAppData) {
                keyValues.push(key + "=" + webAppData[key]);
            }
            keyValues.sort();

            // مرحله 3: ایجاد رشته joined_pairs
            const data_check_string = keyValues.join("\n");

            // مرحله 4: ایجاد secret_key با HMAC-SHA256
            const secret_key = crypto.createHmac('sha256', 'WebAppData')
                .update(token)
                .digest();

            // مرحله 5: ایجاد calculatedHash محاسبه شده با HMAC-SHA256
            const calculatedHash = crypto.createHmac('sha256', secret_key)
                .update(data_check_string)
                .digest('hex');

            // مرحله 6: مقایسه hash دریافتی با hash محاسبه شده
            let isValid = false;
            try {
                isValid = crypto.timingSafeEqual(
                    Buffer.from(calculatedHash, 'hex'),
                    Buffer.from(receivedHash, 'hex')
                );
            } catch (e) {
                isValid = false;
            }

            if (isValid) {
                // استخراج اطلاعات کاربر
                let userData = {};

                if (webAppData.user) {
                    try {
                        const user = JSON.parse(decodeURIComponent(webAppData.user));
                        userData = {
                            id: user.id || null,
                            first_name: user.first_name || null,
                            last_name: user.last_name || null,
                            language_code: user.language_code || null,
                            allows_write_to_pm: user.allows_write_to_pm || false
                        };
                    } catch (e) {
                        userData = {};
                    }
                }

                res.end(JSON.stringify({
                    status: 'success',
                    message: 'داده‌ها معتبر هستند',
                    user: userData
                }));
            } else {
                res.end(JSON.stringify({
                    status: 'error',
                    message: 'داده‌ها نامعتبر هستند'
                }));
            }

        } catch (error) {
            res.writeHead(500);
            res.end(JSON.stringify({
                status: 'error',
                message: 'خطای داخلی سرور'
            }));
        }
    });
});

const PORT = 8080;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});