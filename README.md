⚔️ VergilPanel

A modern, lightweight VLESS management panel powered by Xray

VergilPanel یک پنل مدیریت ساده، مدرن و سبک برای مدیریت کانفیگ‌های VLESS بر پایه‌ی Xray-core است.

هدف VergilPanel اینه که ساخت و مدیریت کانفیگ‌ها، Subscription و کاربران تا حد ممکن ساده باشه؛ بدون اینکه کاربر مجبور باشه با فایل‌های پیچیده‌ی Xray درگیر بشه.

«VergilPanel v1.0 — First Public Release»

---

✨ Features

- ⚔️ VLESS + XHTTP
- 🌐 VLESS + WebSocket
- 🔗 Subscription URL
- 📱 QR Code برای کانفیگ‌ها
- 📋 Copy Config
- 👤 مدیریت کاربران
- ⏳ تاریخ انقضای کاربران
- 🟢 فعال / 🔴 غیرفعال کردن کاربران
- 🔄 همگام‌سازی خودکار Xray
- 🔐 پنل مدیریت با Login
- ⚙️ صفحه Settings
- 🌙 رابط کاربری Dark
- 💙 طراحی Sky Blue / Deep Navy
- 📦 SQLite Database
- 🧠 مدیریت خودکار Xray Configuration
- 🚀 آماده برای Deploy روی Railway

---

🖥️ Preview

«Screenshots will be added soon.»

---

🧩 Architecture

VergilPanel در نسخه‌ی اول به شکل زیر کار می‌کند:

                    Internet
                       │
                       ▼
                Railway HTTPS
                       │
                       ▼
               ┌──────────────┐
               │ VergilPanel  │
               │   Node.js    │
               └──────┬───────┘
                      │
             ┌────────┴────────┐
             ▼                 ▼
          /xhttp              /ws
             │                 │
             ▼                 ▼
       Xray :10001        Xray :10002

در این معماری، Xray مستقیماً روی اینترنت Expose نمی‌شود و VergilPanel درخواست‌ها را به Xray داخلی منتقل می‌کند.

---

🚀 Deploy on Railway

ساده‌ترین روش اجرای VergilPanel در نسخه‌ی اول، استفاده از Railway است.

1. Fork Repository

ابتدا Repository را Fork کنید:

"VergilPanel on GitHub" (https://reference-url-citation.invalid/0)

سپس Repository خودتان را به Railway متصل کنید.

---

2. Create a Railway Project

در Railway:

1. یک Project جدید بسازید.
2. گزینه‌ی Deploy from GitHub Repo را انتخاب کنید.
3. Repository مربوط به VergilPanel را انتخاب کنید.
4. صبر کنید تا Build و Deploy انجام شود.

VergilPanel به‌صورت خودکار:

- Node.js را اجرا می‌کند.
- Xray-core را نصب می‌کند.
- Database را ایجاد می‌کند.
- Configuration مربوط به Xray را می‌سازد.
- Server را روی Port "8080" اجرا می‌کند.

---

🌐 Railway Settings

در بخش Networking، برای سرویس VergilPanel یک Domain ایجاد کنید.

مثلاً:

https://your-project.up.railway.app

مهم

برای نسخه‌ی اول نیازی به Railway TCP Proxy ندارید.

VergilPanel از HTTP/HTTPS و Proxy داخلی خودش استفاده می‌کند.

---

💾 Persistent Storage

برای اینکه اطلاعات کاربران و Database بعد از Restart یا Redeploy باقی بماند، بهتر است یک Volume برای Railway اضافه کنید.

Mount Path:

/app/data

Database در این مسیر ذخیره می‌شود:

/app/data/vergilpanel.db

---

🔐 Default Login

در یک نصب تازه، اطلاعات ورود پیش‌فرض:

Username: admin
Password: admin

بعد از اولین ورود، می‌توانید از قسمت:

Settings

نام کاربری و رمز عبور مدیریت را تغییر دهید.

Environment Variables

در صورت نیاز می‌توانید از Environment Variables نیز استفاده کنید:

ADMIN_USERNAME
ADMIN_PASSWORD

اگر این متغیرها تنظیم شوند، مقادیر آن‌ها برای حساب Administrator استفاده می‌شوند.

---

👤 Creating a User

بعد از ورود به پنل:

Dashboard
    ↓
New User

اطلاعات کاربر را وارد کنید.

VergilPanel به‌صورت خودکار:

1. UUID تولید می‌کند.
2. کاربر را در Database ذخیره می‌کند.
3. Xray Configuration را به‌روزرسانی می‌کند.
4. Xray را Reload/Restart می‌کند.
5. لینک VLESS تولید می‌کند.
6. QR Code تولید می‌کند.
7. Subscription را به‌روزرسانی می‌کند.

---

🔗 Subscription

هر کاربر دارای Subscription مخصوص خودش است.

Subscription شامل کانفیگ‌های فعال کاربر می‌شود.

فرمت کلی:

https://YOUR-DOMAIN/sub/TOKEN

این لینک را می‌توان داخل Clientهای سازگار با Subscription وارد کرد.

---

📱 VLESS Config

VergilPanel در نسخه‌ی اول دو Transport اصلی ارائه می‌دهد:

XHTTP

VLESS + XHTTP + HTTPS

WebSocket

VLESS + WebSocket + HTTPS

برای هر کاربر می‌توانید QR Code یا لینک VLESS را مستقیماً از پنل دریافت کنید.

---

🛡️ Security

در نسخه‌ی اول، TLS در لایه‌ی Public Railway مدیریت می‌شود.

ارتباط داخلی VergilPanel با Xray روی localhost انجام می‌شود:

127.0.0.1:10001
127.0.0.1:10002

Xray مستقیماً روی اینترنت Public نیست.

---

🗃️ Database

VergilPanel از SQLite استفاده می‌کند.

Database:

/app/data/vergilpanel.db

اطلاعاتی مانند کاربران، UUIDها، وضعیت حساب و تاریخ انقضا در Database ذخیره می‌شوند.

---

⚙️ Environment Variables

در حالت عادی، VergilPanel بدون Environment Variable اضافی قابل اجراست.

اختیاری:

Variable| Description
"PORT"| Port مربوط به Web Server
"ADMIN_USERNAME"| Username مدیر
"ADMIN_PASSWORD"| Password مدیر

Port پیش‌فرض:

8080

---

❤️ Powered By

POWERED BY YASIN BEHZAD

VergilPanel یک پروژه‌ی مستقل و Open Source است که با هدف ساده‌تر کردن مدیریت Xray و VLESS ساخته شده است.

---

🧪 Health Check

برای بررسی وضعیت سرویس:

/health

مثال:

https://YOUR-DOMAIN/health

اگر سرویس سالم باشد، پاسخ Health Check نمایش داده می‌شود.

---

🛠️ Local Development

برای اجرای پروژه به‌صورت Local:

Requirements

- Node.js 22+
- npm
- Xray-core

سپس:

git clone https://github.com/ysnusn167/VergilPanel.git
cd VergilPanel
npm install
npm start

پنل به‌صورت پیش‌فرض روی:

http://localhost:8080

اجرا می‌شود.

---

📁 Project Structure

VergilPanel/
│
├── server/
│   └── index.js
│
├── Dockerfile
├── package.json
├── package-lock.json
└── README.md

---

🗺️ Roadmap

v1.0 — Current

- [x] VLESS XHTTP
- [x] VLESS WebSocket
- [x] User Management
- [x] Subscription
- [x] QR Code
- [x] Automatic Xray Configuration
- [x] Admin Settings
- [x] Railway Deployment

v2.0 — Planned

در نسخه‌های بعدی قصد داریم امکانات بیشتری اضافه کنیم، از جمله:

- [ ] VPS Installation
- [ ] Ubuntu / Debian Support
- [ ] One-Click Installer
- [ ] Docker Deployment
- [ ] VLESS TCP
- [ ] VLESS Reality
- [ ] gRPC
- [ ] Trojan
- [ ] VMess
- [ ] Traffic Statistics
- [ ] Bandwidth Limits
- [ ] Multi-Server Management
- [ ] Server Monitoring
- [ ] Advanced User Management
- [ ] Backup & Restore
- [ ] API
- [ ] Better Mobile UI

«Roadmap ممکن است بر اساس نیاز پروژه و بازخورد کاربران تغییر کند.»

---

🤝 Contributing

اگر ایده، پیشنهاد یا Bug پیدا کردید، خوشحال می‌شویم آن را در GitHub مطرح کنید.

برای مشارکت:

Fork
  ↓
Create Branch
  ↓
Make Changes
  ↓
Commit
  ↓
Pull Request

---

🐛 Bug Reports

اگر مشکلی پیدا کردید، لطفاً هنگام گزارش Bug اطلاعات زیر را قرار دهید:

- Version
- Deployment Platform
- Operating System
- Error Message
- Steps to Reproduce

از ارسال اطلاعات حساس مانند Password، API Key یا Token خودداری کنید.

---

⭐ Support the Project

اگر VergilPanel برای شما مفید بود:

⭐ Star کردن Repository در GitHub کمک بزرگی به دیده‌شدن پروژه می‌کند.

همچنین می‌توانید پروژه را Fork کنید و در توسعه‌ی نسخه‌های بعدی مشارکت کنید.

---

📜 License

License information will be added in the repository.

---

⚔️ VergilPanel

Simple. Fast. Powerful.

POWERED BY YASIN BEHZAD

«Built with Node.js, SQLite and Xray-core.»
