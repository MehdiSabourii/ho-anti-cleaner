# HO Anti Cleaner & Optimizer 🛡️
> **افزونه تخصصی ضد بدافزار، جراحی فایل‌های آلوده و بهینه‌سازی دیتابیس وردپرس**  
> **Advanced WordPress Malware Incident Response, Surgical Disinfection & Security Hardening Tool**

---

[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-GPL--2.0%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Author](https://img.shields.io/badge/Developer-ho%20mehdi%20sabour-orange.svg)](#تیم-توسعه-دهنده)
[![Version](https://img.shields.io/badge/Version-2.5.0-brightgreen.svg)](#)

---

## 📖 درباره پروژه (About the Project)

این پروژه در پاسخ به نفوذ بدافزار پیچیده و چندمرحله‌ای موسوم به **Asset Flow** (کلاس `WP_Sys_Optimiser`) و همچنین شناسایی انواع وب‌شل‌ها و تهدیدات رایج وردپرس توسعه یافته است.

برخلاف آنتی‌ویروس‌های مرسوم که صرفاً فایل‌های آلوده را حذف کرده یا کل افزونه را مسدود می‌کنند، این ابزار عمل **«جراحی و ترمیم امن»** را انجام می‌دهد؛ یعنی کد مخرب تزریق‌شده به انتهای فایل‌های PHP را برش داده و بدون از کار افتادن افزونه‌ها یا هسته وردپرس، سایت را به حالت پاک اولیه بازمی‌گرداند.

---

## ⚡ ویژگی‌های برجسته (Key Features)

### ۱. جراحی و پاک‌سازی تخصصی بدافزار Asset Flow
- **جراحی امن کدهای الحاقی:** شناسایی نقطه تزریق بدافزار در فایل‌های PHP و حذف تمیز کد مخرب به همراه ساخت فایل پشتیبان در پوشه قرنطینه امن.
- **کشف و حذف کاربران درپشتی (Hidden Backdoor Admins):** دور زدن فیلتر پنهان‌ساز `pre_user_query` و حذف مستقیم مدیران مخفی با الگوی `sys_*` از دیتابیس.
- **پاک‌سازی ردپاها در دیتابیس:** حذف جداول ردگیری (`wp_sys_av_*`) و رکوردهای مخرب در جدول تنظیمات (`jsonmetafield` و `sub_valid_adm*`).
- **پاک‌سازی پوشه Must-Use Plugins:** خنثی‌سازی و حذف فایل‌های خوداجرا (`01-mu-*.php`) در `wp-content/mu-plugins`.

### ۲. موتور تحلیل اکتشافی برای وب‌شل‌ها و تهدیدات عمومی (Heuristic Engine v2.5.0)
- شناسایی الگوهای اجرای کد مخفی: `eval(base64_decode)`, `gzinflate`, `gzuncompress`, `str_rot13`
- ردیابی اجرای دستورات سرور (RCE): `shell_exec`, `system`, `passthru`, `exec`, `assert` متصل به پارامترهای درخواست کاربر (`$_POST`, `$_GET`, `$_COOKIE`)
- شناسایی وب‌شل‌های نام‌آشنا: **WSO**, **c99**, **r57**, **FilesMan**, **b374k**, **Alfa Shell**, **IndoXploit**
- شناسایی رشته‌های طولانی هگزادسیمال (Hex Obfuscation) و ریدایرکت‌های اسپم جاوااسکریپت.
- تفکیک هوشمند فایل‌های تنظیمات فایروال افزونه‌های امنیتی معتبر (مانند AIOS و Wordfence) و جلوگیری از هشدارهای کاذب (False Positives).

### ۳. بهینه‌سازی و سخت‌سازی امنیت (Optimization & Hardening)
- اجرای `OPTIMIZE TABLE` و دیفرگ تمامی جداول دیتابیس.
- پاک‌سازی خودکار ترنزینت‌های منقضی، رونوشت‌های کهنه پست‌ها (Revisions) و دیدگاه‌های اسپم.
- ارزیابی مجوز فایل‌های حساس (`wp-config.php`, `wp-content`) و بررسی وضعیت خطایابی.
- تولید خودکار و کپی کلیدهای تصادفی تازه Salts جهت ابطال کلیه نشست‌های باز مهاجمان در `wp-config.php`.

### ۴. اسکریپت اضطراری تک‌فایلی (`emergency-cleaner.php`)
- در صورتی که دسترسی به پیشخوان به دلیل خطای `wp_die` یا قفل شدن ادمین قطع باشد، این فایل به صورت مستقل در ریشه سایت اجرا شده و کلیه آلودگی‌ها را پاک‌سازی می‌کند.

---

## 📂 ساختار فایل‌ها (Repository Structure)

```text
├── ho-anti-cleaner/                 # پوشه اصلی افزونه وردپرس
│   ├── ho-anti-cleaner.php          # فایل راه‌انداز اصلی و هدر افزونه
│   ├── emergency-cleaner.php        # ابزار پاک‌سازی اضطراری
│   ├── includes/
│   │   ├── admin-view.php           # رابط کاربری راست‌چین و مدرن داشبورد
│   │   ├── class-scanner.php        # موتور اسکن بازگشتی و تحلیل اکتشافی
│   │   ├── class-cleaner.php        # موتور جراحی فایل‌ها و پاک‌سازی دیتابیس
│   │   ├── class-optimizer.php      # بهینه‌ساز دیتابیس و بررسی سلامت امنیتی
│   │   └── class-ajax.php           # پردازشگر ایمن درخواست‌های AJAX
│   └── assets/
│       ├── css/admin-style.css      # استایل‌های واکنش‌گرا و نشان‌های وضعیت
│       └── js/admin-script.js       # اسکریپت‌های تعاملی و لاگ لحظه‌ای ترمینال
├── emergency-cleaner.php            # نسخه مستقل جهت آپلود مستقیم در ریشه سایت
└── README.md                        # راهنمای کامل پروژه
```

---

## 🚀 نحوه نصب و استفاده (Installation & Usage)

### روش ۱: نصب افزونه در پیشخوان وردپرس
1. پوشه `ho-anti-cleaner` را فشرده (Zip) کنید یا مستقیماً در مسیر `wp-content/plugins/` هاست آپلود نمایید.
2. از پیشخوان وردپرس وارد بخش **افزونه‌ها** شوید و افزونه **HO Anti Cleaner & Optimizer** را فعال کنید.
3. در منوی مدیریت وردپرس وارد بخش **ضد بدافزار HO Anti** شوید.
4. روی دکمه **«اسکن سیستم»** کلیک کنید.
5. پس از پایان اسکن، تهدیدات را بررسی کنید و با دکمه **«پاک‌سازی و ترمیم یک‌کلیکه»** یا جراحی تکی، سایت را پاک‌سازی نمایید.

### روش ۲: استفاده اضطراری در شرایط قطعی پیشخوان
1. فایل `emergency-cleaner.php` را در ریشه هاست وردپرس (کنار `wp-config.php`) آپلود کنید.
2. در مرورگر آدرس `https://yoursite.com/emergency-cleaner.php` را باز کنید.
3. روی دکمه شروع پاک‌سازی کلیک کنید و در انتها دکمه حذف خودکار اسکریپت را بزنید.

---

## 👨‍💻 تیم توسعه‌دهنده (Author & Credits)

- **توسعه داده شده توسط:** `ho mehdi sabour`
- **گیت‌هاب:** [@MehdiSabourii](https://github.com/MehdiSabourii)
- **مجوز:** GPLv2 یا بالاتر
