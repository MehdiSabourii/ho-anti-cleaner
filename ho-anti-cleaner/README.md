# HO Anti Cleaner & Security Shield 🛡️
> **سامانه امنیتی جامع، ضد بدافزار چندلایه، جراحی هوشمند کدهای مخرب، بازگردانی رسمی هسته و سپر ضد تزریق وردپرس**  
> **Enterprise Multi-Layer WordPress Security Suite, Safe Remediation (Repair Before Delete), File Integrity & Host Agent**

---

[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%20--%208.3-purple.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-GPL--2.0%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Author](https://img.shields.io/badge/Developer-ho%20mehdi%20sabour-orange.svg)](#تیم-توسعه-دهنده)
[![Version](https://img.shields.io/badge/Version-3.2.0-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen.svg)](#)

---

## 📖 درباره پروژه (About the Project)

سامانه **HO Anti Cleaner & Security Shield** یک راهکار جامع و Production-Grade برای پیشگیری، شناسایی، تحلیل، مهار و اصلاح آسیب‌پذیری‌ها و تهدیدهای امنیتی وردپرس و سطح هاست است.

این ابزار با رعایت سیاست الزامی **«Repair Before Delete»** از حذف کورکورانه فایل‌ها جلوگیری کرده و اولویت نخست را بر بازگردانی امن فایل‌های هسته از مراجع رسمی، جراحی دقیق کدهای تزریق‌شده و ثبت مانیفست کامل جهت امکان بازگردانی (Rollback) قرار داده است.

---

## ⚡ معماری و قابلیت‌های برجسته (Key Features)

### ۱. سیاست الزامی اصلاح امن (Repair Before Delete)
- **جایگزینی مستقیم از منبع معتبر (Core File Restore):** اتصال مستقیم به مخزن رسمی `api.wordpress.org`، مقایسه هش MD5 و امکان بارگیری و جایگزینی فایل سالم و معتبر همان نسخه وردپرس با یک کلیک.
- **جراحی دقیق و اعتبارسنجی نحوی (Surgical Repair & Syntax Guard):** برش کدهای مخرب هدر (مانند گیت‌کیپرهای لاگین) و فوتر (مانند بدافزار Asset Flow) به همراه تحلیل نحوی با توکن‌ساز PHP (`validate_php_syntax`) جهت جلوگیری کامل از بروز خطای Fatal Error و سفید شدن سایت.
- **سامانه قرنطینه ایزوله و بازگردانی خودکار (Quarantine & Rollback):** ذخیره بسته‌های قبل از اصلاح به صورت کدگذاری‌شده با پسوند امن `.quarantine` و مسدودسازی وب در سطح Apache, Nginx, IIS، همراه با ثبت در مانیفست و امکان بازگردانی (Rollback) بایت‌به‌بایت.

### ۲. موتورهای تشخیصی چندلایه (Multi-Layer Detection Adapters)
- **موتور یکپارچگی فایل‌های هسته (Core File Integrity):** بررسی کلیه فایل‌های اصلی وردپرس با چکسام‌های رسمی نسخه متناظر و تولید گزارش تفاوت (Diff Viewer) خط‌به‌خط.
- **موتور امضا و تحلیل معنایی (Malware & Token Analyzer):** شناسایی وب‌شل‌های نام‌آشنا (WSO, c99, r57, b374k, Weevely, Alfa, IndoXploit) و کدهای مبهم‌سازی‌شده پویا (`eval + base64/gzinflate`) با کاهش خطای مثبت (Zero False Positives روی تصاویر base64 یا افزونه‌های معتبر).
- **پایش نقاط ماندگاری و دیتابیس (Persistence & DB Guard):** بازرسی عمیق فایل‌های Drop-in (`advanced-cache.php`, `object-cache.php`)، پوشه `mu-plugins`، هوک‌های مشکوک در WP-Cron، کدهای تزریقی در `wp-config.php` و قالب فعال، و ردیابی مدیران مخفی (`sys_*`).
- **هوش آسیب‌پذیری‌ها (Vulnerability Intelligence):** ردیابی نسخه‌های منسوخ و دارای ریسک امنیتی در هسته، افزونه‌ها و قالب‌ها.

### ۳. اسکن دسته‌ای بهینه (Chunked / Batch Scanning)
- تقسیم هوشمند فایل‌ها به بسته‌های ۱۵۰تایی جهت جلوگیری کامل از اتمام زمان اجرای اسکریپت (Timeout) و سرریز حافظه در سایت‌های پرترافیک و بزرگ.

### ۴. پایش سطح هاست و ایجنت سرور (Host Security Agent)
- مؤلفه مستقل لینوکس (`host-agent/gravity-agent.py`) با ارتباط امن و احراز اصالت‌شده HMAC-SHA256، اولویت پایین پردازشی (`nice 19`) و ادغام با **Linux Malware Detect (LMD)**.
- اعلام کاملاً شفاف وضعیت: در صورت عدم نصب یا هاست اشتراکی، وضعیت به صورت «نیازمند دسترسی سرور» گزارش شده و ادعای کاذب نمی‌شود.

### ۵. سپر فعال ضد تزریق (Active Anti-Injection Shield)
- **قفل ضد بازنویسی فایل‌ها (0444 Immunity Lock):** قفل فایل‌های حساس ورودی جهت مسدودسازی بازنویسی توسط پروسه‌های PHP.
- **نگهبان خودترمیم‌کننده (Self-Healing Guard):** جراحی و رفع آلودگی خودکار و بلادرنگ در اولین درخواست.
- **سپرهای محافظتی Uploads و wp-includes:** استقرار قوانین سخت‌گیرانه وب‌سرور جهت مهار اجرای فایل‌های اجرایی.

---

## 📂 ساختار ماژولار پروژه (Repository Structure)

```text
├── ho-anti-cleaner/                     # افزونه اصلی وردپرس
│   ├── ho-anti-cleaner.php              # راه‌انداز اصلی و هدر افزونه (v3.1.0)
│   ├── emergency-cleaner.php            # ابزار پاک‌سازی اضطراری مستقل
│   ├── includes/
│   │   ├── models/
│   │   │   └── class-finding.php        # مدل استاندارد یافته‌ها (Standard Finding Model)
│   │   ├── contracts/
│   │   │   └── interface-detection-adapter.php # اینترفیس آداپتورهای تشخیص
│   │   ├── remediation/
│   │   │   ├── class-quarantine-manager.php    # سامانه قرنطینه امن و مانیفست Rollback
│   │   │   └── class-safe-repair.php           # موتور جراحی امن و بازگردانی رسمی هسته
│   │   ├── engines/
│   │   │   ├── class-file-integrity-engine.php # موتور یکپارچگی فایل و استخراج چکسام
│   │   │   ├── class-malware-engine.php        # موتور امضا و تحلیل معنایی توکن‌های PHP
│   │   │   ├── class-persistence-engine.php    # پایش ماندگاری، دیتابیس و کران‌جاب‌ها
│   │   │   └── class-vulnerability-engine.php  # هوش آسیب‌پذیری‌های هسته و افزونه‌ها
│   │   ├── scanner/
│   │   │   └── class-batch-scanner.php         # هماهنگ‌کننده اسکن دسته‌ای و پله‌ای
│   │   ├── host-agent/
│   │   │   └── class-host-agent-bridge.php     # رابط ارتباط با ایجنت سروری
│   │   ├── rules/
│   │   │   └── class-rule-manager.php          # مدیریت امن و نسخه‌بندی قواعد
│   │   ├── class-protection.php         # سپر ضد تزریق، قفل 0444 و خودترمیم‌کننده
│   │   ├── class-scanner.php            # اسکنر تکمیلی و امضاهای محلی
│   │   ├── class-cleaner.php            # موتور پاک‌سازی و رفع آلودگی
│   │   ├── class-optimizer.php          # بهینه‌ساز دیتابیس و بررسی سلامت
│   │   ├── class-ajax.php               # کنترلر پردازش امن درخواست‌های AJAX
│   │   └── admin-view.php               # رابط کاربری راست‌چین و مدرن
│   └── assets/
│       ├── css/admin-style.css          # استایل‌های واکنش‌گرا و نشان‌های وضعیت
│       └── js/admin-script.js           # اسکریپت‌های تعاملی، Rollback و اسکن دسته‌ای
├── host-agent/                          # سرویس مستقل پایش هاست لینوکس
│   ├── gravity-agent.py                 # دیمون مستقل پایتون با اتصال LMD
│   └── README.md                        # راهنمای استقرار در سرور لینوکس
├── tests/                               # مجموعه آزمون‌های خودکار و کنترل کیفیت
│   └── run-gravity-test-suite.php       # اسکریپت آزمون‌های پذیرش ۱۷گانه
├── emergency-cleaner.php                # اسکریپت اضطراری مستقل ریشه سایت
└── README.md                            # راهنمای کامل پروژه
```

---

## 🧪 آزمون‌های کنترل کیفیت و پذیرش (Acceptance Tests)

پروژه دارای مجموعه آزمون‌های واقعی و ایزوله در فایل `tests/run-gravity-test-suite.php` است:
- **آزمون‌های مثبت:** تشخیص وب‌شل WSO، کدهای چندمرحله‌ای eval/base64/gzinflate، بدافزار Asset Flow، درپشتی‌های mu-plugins و کران‌جاب‌های مشکوک.
- **آزمون‌های منفی (Zero False Positive):** عدم ایجاد هشدار برای استفاده‌های مشروع از base64_decode، عدم حذف فایلهای index.php و اعلان دقیق عدم پوشش هاست در صورت نبود ایجنت.
- **آزمون‌های اصلاح و Rollback:** جراحی کد مسدودکننده لاگین، تأیید عدم خطای گرامری PHP، ثبت در مانیفست، بازیابی بایت‌به‌بایت فایل از قرنطینه و فعال بودن نگهبان نحوی (Syntax Guard).

---

## 👨‍💻 تیم توسعه‌دهنده (Author & Credits)

- **توسعه‌دهنده:** `ho mehdi sabour`
- **گیت‌هاب:** [@MehdiSabourii](https://github.com/MehdiSabourii)
- **مجوز:** GPLv2 یا بالاتر
