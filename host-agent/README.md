# Gravity Host Security Agent 🛡️

سرویس مستقل لینوکس جهت پایش سطح هاست، فایلهای خارج از ریشه وب و ادغام با **Linux Malware Detect (LMD)**.

## ویژگی‌ها
- **ارتباط احراز اصالت‌شده با وردپرس:** استفاده از امضای دیجیتال HMAC-SHA256 بر پایه توکن مشترک.
- **حداقل دسترسی لازم:** اجرای ایجنت در سطح کاربری محدود (کاهش سطح حمله به جای دسترسی Root دائم).
- **مهار بار سخت‌افزاری:** اعمال خودکار `os.nice(19)` جهت تضمین عدم اشغال منابع CPU و I/O هاست.
- **محدودیت مسیرها:** اجرای اسکن صرفاً در مسیرهای مجاز تعریف‌شده در فایل پیکربندی.
- **گزارش‌دهی شفاف وضعیت:** در صورت عدم نصب یا نبود دسترسی روت، افزونه وضعیت را به عنوان «غیرفعال (نیازمند دسترسی سرور)» نمایش می‌دهد و هیچ ادعای کذبی صورت نمی‌گیرد.

## راهنمای نصب در سرور لینوکس (اختیاری)

1. ایجاد دایرکتوری و کاربر ایجنت:
```bash
sudo useradd -r -s /bin/false gravity-agent
sudo mkdir -p /etc/gravity-agent /var/log/gravity-agent
sudo chown -R gravity-agent:gravity-agent /var/log/gravity-agent
```

2. پیکربندی در `/etc/gravity-agent/config.json`:
```json
{
  "secret_token": "YOUR_STRONG_SECRET_TOKEN_HERE",
  "monitored_paths": ["/var/www/html/"],
  "scan_interval_hours": 12,
  "max_cpu_percent": 20
}
```

3. تنظیم سرویس Systemd در `/etc/systemd/system/gravity-agent.service`:
```ini
[Unit]
Description=Gravity Host Security Agent
After=network.target

[Service]
Type=simple
User=gravity-agent
ExecStart=/usr/bin/python3 /opt/gravity-agent/gravity-agent.py --config /etc/gravity-agent/config.json
Restart=on-failure
Nice=19

[Install]
WantedBy=multi-user.target
```

4. فعال‌سازی سرویس:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gravity-agent
```

5. در پیشخوان افزونه در وردپرس، مقدار `secret_token` را در تنظیمات ایجنت هاست وارد کنید تا نشان وضعیت به **«متصل و فعال»** تغییر یابد.
