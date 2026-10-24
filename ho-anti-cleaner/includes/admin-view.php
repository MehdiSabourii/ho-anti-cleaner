<?php
/**
 * Admin Dashboard View for HO Anti Cleaner & Security Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

$security_checks  = class_exists( 'HO_Anti_Optimizer' ) ? HO_Anti_Optimizer::audit_security_health() : [];
$lock_status      = class_exists( 'HO_Anti_Protection' ) ? HO_Anti_Protection::get_lock_status() : [];
$self_healing     = (bool) get_option( 'ho_anti_self_healing_enabled', 1 );
$firewall_on      = (bool) get_option( 'ho_anti_firewall_enabled', 1 );
$is_locked        = (bool) get_option( 'ho_anti_files_locked', 1 );
$security_logs    = class_exists( 'HO_Anti_Protection' ) ? HO_Anti_Protection::get_security_logs() : [];
$cron_report      = class_exists( 'HO_Anti_Protection' ) ? HO_Anti_Protection::audit_cron_jobs() : [ 'total' => 0, 'suspicious' => [] ];
$quarantine_stats = class_exists( 'HO_Anti_Quarantine_Manager' ) ? HO_Anti_Quarantine_Manager::get_quarantine_stats() : [ 'total' => 0, 'active' => 0, 'restored' => 0, 'items' => [] ];
$host_status      = class_exists( 'HO_Anti_Host_Agent_Bridge' ) ? HO_Anti_Host_Agent_Bridge::get_agent_status() : [ 'is_active' => false, 'label' => 'غیرفعال' ];
?>

<div class="wrap afc-wrap" dir="rtl">

    <?php if ( ! empty( $direct_notices ) ): ?>
        <?php foreach ( $direct_notices as $note ): ?>
            <div class="notice notice-success is-dismissible" style="padding: 14px 18px; font-size: 14px; border-right-color: #16a34a; margin-bottom: 20px;">
                <strong><span class="dashicons dashicons-yes-alt"></span> عملیات موفق:</strong> <?php echo esc_html( $note ); ?>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <!-- هدر اصلی داشبورد -->
    <div class="afc-header">
        <div class="afc-header-title">
            <span class="dashicons dashicons-shield afc-header-icon"></span>
            <div>
                <h1>
                    ضد بدافزار و سپر امنیتی HO Anti (توسعه: ho mehdi sabour)
                    <span class="afc-badge afc-badge-safe" style="font-size: 11px; margin-right: 8px; vertical-align: middle;">نسخه <?php echo esc_html( HO_ANTI_VERSION ); ?></span>
                </h1>
                <p class="afc-header-subtitle">شناسایی و جراحی کدهای مخرب (Asset Flow و گیت‌کیپرهای ورود)، قفل ضد بازنویسی فایل‌ها و خودترمیم‌کننده فعال</p>
            </div>
        </div>
        <div class="afc-header-actions">
            <form method="post" style="display:inline-block;" onsubmit="return confirm('آیا از اجرای پاک‌سازی و ترمیم کلیه فایل‌ها، دیتابیس و قفل‌گذاری محافظتی اطمینان دارید؟');">
                <button type="submit" name="afc_direct_action" value="clean_all_direct" class="button button-danger afc-btn-hero">
                    <span class="dashicons dashicons-shield"></span> پاک‌سازی و قفل اضطراری (مستقیم)
                </button>
            </form>
            <button id="afc-btn-quick-scan" class="button button-primary afc-btn-hero">
                <span class="dashicons dashicons-search"></span> اسکن هوشمند سیستم
            </button>
        </div>
    </div>

    <!-- کارت‌های آمار و وضعیت اولیه -->
    <div class="afc-stats-grid">
        <div class="afc-stat-card afc-card-status" id="afc-card-overall">
            <div class="afc-stat-icon dashicons dashicons-heart"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">وضعیت کلی سایت</span>
                <span class="afc-stat-value" id="afc-val-status">آماده بررسی</span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-lock"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">قفل محافظتی فایل‌ها</span>
                <span class="afc-stat-value" id="afc-val-locked"><?php echo $is_locked ? 'فعال (0444)' : 'باز (0644)'; ?></span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-admin-users"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">کاربران مخفی (Backdoor)</span>
                <span class="afc-stat-value" id="afc-val-users">-</span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-database"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">ردپای دیتابیس (جداول/آپشن‌ها)</span>
                <span class="afc-stat-value" id="afc-val-db">-</span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-media-code"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">فایل‌های آلوده (PHP)</span>
                <span class="afc-stat-value" id="afc-val-files">-</span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-wordpress"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">ناهماهنگی هسته (غیررسمی)</span>
                <span class="afc-stat-value" id="afc-val-core">-</span>
            </div>
        </div>
    </div>

    <!-- نوار پیشرفت عملیات -->
    <div id="afc-progress-box" class="afc-progress-box" style="display: none;">
        <div class="afc-progress-bar-container">
            <div id="afc-progress-bar" class="afc-progress-bar"></div>
        </div>
        <div class="afc-progress-text">
            <span id="afc-progress-msg">در حال پردازش اطلاعات...</span>
            <span class="spinner is-active" style="float:none; margin:0 5px;"></span>
        </div>
    </div>

    <!-- زبانه‌های ناوبری داشبورد -->
    <div class="afc-tabs-nav">
        <a href="#tab-shield" class="afc-tab-btn active" data-tab="tab-shield">
            <span class="dashicons dashicons-shield-alt"></span> سپر ضد تزریق و امنیت فعال
        </a>
        <a href="#tab-scan" class="afc-tab-btn" data-tab="tab-scan">
            <span class="dashicons dashicons-visibility"></span> نتایج اسکن و تهدیدات
        </a>
        <a href="#tab-remediate" class="afc-tab-btn" data-tab="tab-remediate">
            <span class="dashicons dashicons-trash"></span> جعبه‌ابزار پاک‌سازی و جراحی
        </a>
        <a href="#tab-quarantine" class="afc-tab-btn" data-tab="tab-quarantine">
            <span class="dashicons dashicons-archive"></span> مدیریت قرنطینه و بازگردانی (Rollback)
        </a>
        <a href="#tab-host" class="afc-tab-btn" data-tab="tab-host">
            <span class="dashicons dashicons-networking"></span> پایش سطح هاست و ایجنت سرور
        </a>
        <a href="#tab-optimize" class="afc-tab-btn" data-tab="tab-optimize">
            <span class="dashicons dashicons-performance"></span> بهینه‌سازی دیتابیس و امنیت
        </a>
        <a href="#tab-logs" class="afc-tab-btn" data-tab="tab-logs">
            <span class="dashicons dashicons-editor-code"></span> لاگ زنده و حوادث امنیتی
        </a>
    </div>

    <!-- محتوای زبانه‌ها -->
    <div class="afc-tab-content-wrapper">

        <!-- زبانه ۱ (پیش‌فرض): سپر ضد تزریق و محافظت بلادرنگ -->
        <div id="tab-shield" class="afc-tab-pane active">

            <!-- کارت معرفی وضعیت قفل ضد تزریق -->
            <div class="afc-box" style="margin-bottom: 25px; border-right: 4px solid #3b82f6;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px;">
                    <div>
                        <h2 style="margin:0 0 8px 0; font-size:18px;">
                            <span class="dashicons dashicons-lock" style="color:#2563eb;"></span>
                            قفل ضد بازنویسی فایل‌های حساس (0444 Immunity Lock)
                        </h2>
                        <p style="margin:0; color:#475569; max-width:750px; font-size:13.5px; line-height:1.7;">
                            وقتی فایل‌های کلیدی مانند <code>wp-login.php</code>، <code>index.php</code> و <code>wp-config.php</code> در وضعیت فقط خواندنی (0444) قفل شوند، پروسه‌های PHP هاست و کدهای مخرب تزریقی قادر به بازنویسی و افزودن کدهای مسدودکننده (مانند <code>die();</code> یا گیت‌کیپرهای کوکی) به آن‌ها نخواهند بود.
                        </p>
                    </div>
                    <div style="display:flex; gap:10px;">
                        <button id="afc-btn-lock-files" class="button button-primary button-hero" style="background:#16a34a; border-color:#15803d;">
                            <span class="dashicons dashicons-lock"></span> قفل کردن فایل‌ها (0444)
                        </button>
                        <button id="afc-btn-unlock-files" class="button button-secondary button-hero">
                            <span class="dashicons dashicons-unlock"></span> باز کردن موقت قفل (0644)
                        </button>
                    </div>
                </div>
            </div>

            <!-- جدول وضعیت مجوز فایل‌های حساس -->
            <div class="afc-box" style="margin-bottom: 25px;">
                <h3 style="margin-top:0;"><span class="dashicons dashicons-media-document"></span> وضعیت محافظت فایل‌های ورودی وردپرس</h3>
                <table class="afc-table" id="afc-table-file-locks">
                    <thead>
                        <tr>
                            <th>نام فایل</th>
                            <th>مسیر نسبی</th>
                            <th>مجوز فعلی</th>
                            <th>وضعیت امنیتی</th>
                            <th>دسترسی نوشتن</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $lock_status as $st ): ?>
                            <tr>
                                <td><strong><code><?php echo esc_html( $st['name'] ); ?></code></strong></td>
                                <td><code style="font-size:11px;"><?php echo esc_html( str_replace( ABSPATH, '', $st['path'] ) ); ?></code></td>
                                <td><span class="afc-badge"><?php echo esc_html( $st['perms'] ); ?></span></td>
                                <td>
                                    <?php if ( $st['locked'] ): ?>
                                        <span class="afc-badge afc-badge-safe"><span class="dashicons dashicons-yes"></span> قفل‌شده و ضد تزریق</span>
                                    <?php else: ?>
                                        <span class="afc-badge afc-badge-warning"><span class="dashicons dashicons-warning"></span> قابل نوشتن (توصیه: قفل شود)</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( $st['writable'] ): ?>
                                        <span style="color:#dc2626; font-weight:bold;">بله (آسیب‌پذیر به بازنویسی)</span>
                                    <?php else: ?>
                                        <span style="color:#16a34a; font-weight:bold;">خیر (محافظت‌شده)</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- تنظیمات ماژول‌های فعال حفاظتی -->
            <div class="afc-grid-2" style="margin-bottom:25px;">

                <!-- ماژول خودترمیم‌کننده -->
                <div class="afc-box">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div>
                            <h3 style="margin:0 0 6px 0;"><span class="dashicons dashicons-update"></span> نگهبان خودترمیم‌کننده (Self-Healing Guard)</h3>
                            <p style="margin:0; font-size:13px; color:#475569; line-height:1.6;">
                                در صورتی که کران‌جاب یا پروسه پنهانی روی سرور مجدداً کدهای مسدودکننده (گیت‌کیپرهای لاگین یا کوکی <code>yrxc_u</code>) را در <code>wp-login.php</code> یا فایل‌های ریشه بنویسد، این سیستم به محض اولین فراخوانی فایل را بلافاصله جراحی و به حالت پاک بازمی‌گرداند.
                            </p>
                        </div>
                        <label class="afc-switch" style="margin-right:15px;">
                            <input type="checkbox" id="afc-toggle-self-heal" <?php checked( $self_healing ); ?>>
                            <span class="afc-slider"></span>
                        </label>
                    </div>
                </div>

                <!-- فایروال پیشگیرانه -->
                <div class="afc-box">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div>
                            <h3 style="margin:0 0 6px 0;"><span class="dashicons dashicons-shield"></span> فایروال پیشگیرانه (Micro-WAF)</h3>
                            <p style="margin:0; font-size:13px; color:#475569; line-height:1.6;">
                                درخواست‌های مهاجمان حاوی کوکی‌های بدافزار (مانند <code>yrxc_uck</code>)، تلاش‌های تزریق کد RCE یا دسترسی به وب‌شل‌ها را قبل از رسیدن به هسته وردپرس با خطای ۴۰۳ بلاک می‌کند.
                            </p>
                        </div>
                        <label class="afc-switch" style="margin-right:15px;">
                            <input type="checkbox" id="afc-toggle-waf" <?php checked( $firewall_on ); ?>>
                            <span class="afc-slider"></span>
                        </label>
                    </div>
                </div>

                <!-- مسدودسازی اجرای PHP در آپلودها -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-upload"></span></div>
                    <h3>سپر امنیتی پوشه Uploads و wp-includes</h3>
                    <p style="font-size:13px; color:#475569; line-height:1.6;">
                        استقرار قوانین <code>.htaccess</code> برای جلوگیری از اجرای هرگونه فایل PHP، وب‌شل یا اسکریپت در پوشه رسانه‌ها و بخش اینکلودها.
                    </p>
                    <button id="afc-btn-install-shields" class="button button-primary">
                        استقرار سپر محافظتی Uploads
                    </button>
                </div>

                <!-- سخت‌سازی پیشخوان و wp-config.php -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-admin-tools"></span></div>
                    <h3>غیرفعال‌سازی ویرایشگر فایل در پیشخوان</h3>
                    <p style="font-size:13px; color:#475569; line-height:1.6;">
                        افزودن دستور <code>DISALLOW_FILE_EDIT</code> به فایل <code>wp-config.php</code> جهت جلوگیری از دستکاری قالب‌ها و افزونه‌ها از طریق پنل وردپرس.
                    </p>
                    <button id="afc-btn-harden-config" class="button button-secondary">
                        سخت‌سازی wp-config.php
                    </button>
                </div>

            </div>

            <!-- بررسی کران‌جاب‌های وردپرس (WP-Cron Watchdog) -->
            <div class="afc-box">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <div>
                        <h3 style="margin:0;"><span class="dashicons dashicons-clock"></span> نگهبان کران‌جاب‌های وردپرس (WP-Cron Watchdog)</h3>
                        <p style="margin:0; font-size:13px; color:#64748b;">بررسی وظایف زمان‌بندی‌شده جهت کشف کران‌های مخربی که فایل‌ها را در پس‌زمینه دوباره آلوده می‌کنند.</p>
                    </div>
                    <button id="afc-btn-clean-crons" class="button button-secondary">
                        پاک‌سازی کران‌های مشکوک
                    </button>
                </div>

                <?php if ( empty( $cron_report['suspicious'] ) ): ?>
                    <p style="color:#16a34a; margin:0;"><span class="dashicons dashicons-yes-alt"></span> تمامی <?php echo (int) $cron_report['total']; ?> وظیفه زمان‌بندی‌شده بررسی شدند و هیچ کران‌جاب مشکوکی یافت نشد.</p>
                <?php else: ?>
                    <div class="notice notice-error inline" style="margin:0 0 10px 0;">
                        <p>تعداد <?php echo count( $cron_report['suspicious'] ); ?> رویداد زمان‌بندی‌شده مشکوک شناسایی شد!</p>
                    </div>
                    <table class="afc-table">
                        <thead><tr><th>قلاب (Hook)</th><th>تاریخ اجرا</th><th>علت سوءظن</th></tr></thead>
                        <tbody>
                            <?php foreach ( $cron_report['suspicious'] as $c ): ?>
                                <tr>
                                    <td><code><?php echo esc_html( $c['hook'] ); ?></code></td>
                                    <td><?php echo esc_html( $c['date'] ); ?></td>
                                    <td><span class="afc-badge afc-badge-danger"><?php echo esc_html( $c['reason'] ); ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

        </div>

        <!-- زبانه ۲: اسکن و جزئیات یافته‌ها -->
        <div id="tab-scan" class="afc-tab-pane">
            <div id="afc-empty-state" class="afc-box afc-empty-state">
                <div class="dashicons dashicons-shield-alt afc-empty-icon"></div>
                <h2>اسکن هوشمند فایل‌ها، ریشه و پایگاه داده</h2>
                <p>جهت بررسی عمیق دیتابیس، فایل‌های ریشه وردپرس (از جمله wp-login.php)، هسته و پوشه wp-content روی دکمه زیر کلیک کنید.</p>
                <button class="button button-primary afc-btn-start-scan">شروع اسکن کامل</button>
            </div>

            <div id="afc-scan-results" style="display:none;">
                <!-- ۱. فایل‌های PHP آلوده -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-media-code"></span> فایل‌های PHP آلوده شده در سیستم (هسته، قالب‌ها و ریشه)</h3>
                        <span id="afc-badge-files" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-files" class="afc-section-body"></div>
                </div>

                <!-- ۲. کاربران مخفی -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-admin-users"></span> کاربران مخفی با دسترسی مدیر (Hidden Admins)</h3>
                        <span id="afc-badge-users" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-users" class="afc-section-body"></div>
                </div>

                <!-- ۳. جداول و آپشن‌های دیتابیس -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-database"></span> جداول و تنظیمات تزریق‌شده در دیتابیس</h3>
                        <span id="afc-badge-db" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-db" class="afc-section-body"></div>
                </div>

                <!-- ۴. فایل‌های mu-plugins -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-admin-plugins"></span> فایل‌های خوداجرا در پوشه mu-plugins</h3>
                        <span id="afc-badge-mu" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-mu" class="afc-section-body"></div>
                </div>

                <!-- ۵. فایل‌های مشکوک در آپلودها -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-upload"></span> فایل‌های PHP غیرمجاز در پوشه Uploads</h3>
                        <span id="afc-badge-uploads" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-uploads" class="afc-section-body"></div>
                </div>

                <!-- ۶. فایل‌های تغییریافته یا غیررسمی هسته وردپرس (Core File Integrity) -->
                <div class="afc-section-box" id="afc-box-core">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-wordpress"></span> فایل‌های هسته وردپرس (فایل‌های تغییریافته یا غیررسمی / تزریق به wp-admin)</h3>
                        <span id="afc-badge-core" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-core" class="afc-section-body"></div>
                </div>

                <!-- ۷. هشدار دستکاری آدرس سایت (Site URL Hijacking) -->
                <div class="afc-section-box" id="afc-box-siteurl" style="display:none; border-right: 4px solid #dc2626;">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-admin-site-alt3"></span> هشدار بحرانی: دستکاری آدرس اصلی سایت (Site URL Tampered)</h3>
                        <span id="afc-badge-siteurl" class="afc-badge afc-badge-danger">تغییریافته</span>
                    </div>
                    <div id="afc-list-siteurl" class="afc-section-body"></div>
                </div>
            </div>
        </div>

        <!-- زبانه ۳: ابزار پاک‌سازی و جراحی دستی/خودکار -->
        <div id="tab-remediate" class="afc-tab-pane">
            <div class="afc-grid-2">
                <!-- کارت ۱: پاک‌سازی دیتابیس -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-database-remove"></span></div>
                    <h3>پاک‌سازی دیتابیس وردپرس</h3>
                    <p>حذف کاربران با الگوی <code>sys_*</code>، حذف جداول ردگیری <code>wp_sys_av_*</code> و حذف آپشن‌های <code>jsonmetafield</code> و <code>sub_valid_adm*</code> از دیتابیس.</p>
                    <button id="afc-act-clean-db" class="button button-primary">
                        اجرای پاک‌سازی دیتابیس
                    </button>
                </div>

                <!-- کارت ۲: پاک‌سازی mu-plugins -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-dismiss"></span></div>
                    <h3>حذف درپشتی‌های Must-Use</h3>
                    <p>پوشه <code>wp-content/mu-plugins</code> را از فایل‌های مخرب ایجادشده با نام <code>01-mu-*.php</code> پاک‌سازی می‌کند.</p>
                    <button id="afc-act-clean-mu" class="button button-primary">
                        پاک‌سازی پوشه mu-plugins
                    </button>
                </div>

                <!-- کارت ۳: جراحی و ترمیم تمام فایل‌ها -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-hammer"></span></div>
                    <h3>ترمیم و جراحی فایل‌های آلوده</h3>
                    <p>کدهای مخرب تزریق‌شده به ابتدای فایل‌ها (گیت‌کیپرهای wp-login) یا انتهای فایل‌های PHP را با دقت حذف کرده و فایل را به وضعیت سالم بازمی‌گرداند.</p>
                    <button id="afc-act-clean-files" class="button button-primary">
                        ترمیم فایل‌های آلوده شناسایی‌شده
                    </button>
                </div>

                <!-- کارت ۴: پاک‌سازی uploads -->
                <div class="afc-box">
                    <div class="afc-box-icon"><span class="dashicons dashicons-trash"></span></div>
                    <h3>پاک‌سازی فایل‌های PHP در uploads</h3>
                    <p>پوشه رسانه (Uploads) نباید دارای فایل PHP باشد. این ابزار وب‌شل‌های احتمالی را از این مسیر حذف می‌کند.</p>
                    <button id="afc-act-clean-uploads" class="button button-primary">
                        پاک‌سازی PHPهای پوشه uploads
                    </button>
                </div>
            </div>
        </div>

        <!-- زبانه ۴: بهینه‌سازی دیتابیس و امنیت -->
        <div id="tab-optimize" class="afc-tab-pane">
            <div class="afc-box" style="margin-bottom: 25px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3 style="margin-top:0;"><span class="dashicons dashicons-performance"></span> بهینه‌سازی کامل پایگاه داده وردپرس</h3>
                        <p style="margin-bottom:0;">اجرای <code>OPTIMIZE TABLE</code> روی تمام جداول، پاک‌سازی رونوشت‌های کهنه، ترنزینت‌های منقضی و دیدگاه‌های اسپم جهت سبک‌سازی و افزایش سرعت سایت.</p>
                    </div>
                    <form method="post" style="display:inline-block;">
                        <button type="submit" name="afc_direct_action" value="optimize_db_direct" class="button button-primary button-hero">
                            بهینه‌سازی مستقیم دیتابیس
                        </button>
                    </form>
                </div>
            </div>

            <!-- ارزیابی سلامت امنیتی -->
            <div class="afc-box" style="margin-bottom: 25px;">
                <h3><span class="dashicons dashicons-privacy"></span> بررسی سلامت امنیتی و سطوح دسترسی فایل‌ها</h3>
                <table class="afc-table">
                    <thead>
                        <tr>
                            <th>مورد بررسی</th>
                            <th>وضعیت</th>
                            <th>توضیحات و پیشنهاد</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $security_checks as $chk ): ?>
                            <tr>
                                <td><strong><?php echo esc_html( $chk['title'] ); ?></strong></td>
                                <td>
                                    <?php if ( 'good' === $chk['status'] ): ?>
                                        <span class="afc-badge afc-badge-safe">ایمن</span>
                                    <?php elseif ( 'warning' === $chk['status'] ): ?>
                                        <span class="afc-badge afc-badge-warning">نیاز به بررسی</span>
                                    <?php else: ?>
                                        <span class="afc-badge afc-badge-danger">خطرناک</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html( $chk['detail'] ); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- تولید کلیدهای امنیتی تازه (Salts) -->
            <div class="afc-box">
                <h3><span class="dashicons dashicons-admin-network"></span> تولید کلیدهای امنیتی تازه (WordPress Security Salts)</h3>
                <p>حتماً پس از پاک‌سازی، کلیدهای امنیتی زیر را کپی کرده و در فایل <code>wp-config.php</code> جایگزین کنید تا همه نشست‌های باز مهاجمان باطل شوند:</p>
                <button id="afc-btn-get-salts" class="button button-secondary" style="margin-bottom: 10px;">
                    تولید کلیدهای جدید تصادفی
                </button>
                <div id="afc-salts-container" style="display:none;">
                    <textarea id="afc-salts-text" readonly rows="9" style="width:100%; direction:ltr; font-family:monospace; font-size:12px; background:#f9f9f9;"></textarea>
                    <button id="afc-copy-salts" class="button button-primary" style="margin-top:5px;">کپی در کلیپ‌بورد</button>
                </div>
            </div>
        </div>

        <!-- زبانه ۵: لاگ زنده و تاریخچه حوادث امنیتی -->
        <div id="tab-logs" class="afc-tab-pane">

            <!-- حوادث امنیتی ثبت شده توسط فایروال و خودترمیم‌کننده -->
            <div class="afc-box" style="margin-bottom:25px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="margin:0;"><span class="dashicons dashicons-shield"></span> تاریخچه حملات مسدودشده، تغییرات و خودترمیم‌های انجام‌شده</h3>
                    <div>
                        <button id="afc-btn-refresh-sec-logs" class="button button-primary" style="margin-left:8px;">
                            <span class="dashicons dashicons-update"></span> به‌روزرسانی لاگ‌ها
                        </button>
                        <button id="afc-btn-clear-sec-logs" class="button button-secondary">پاک‌کردن تاریخچه حوادث</button>
                    </div>
                </div>

                <div id="afc-sec-logs-list">
                    <?php if ( empty( $security_logs ) ): ?>
                        <p style="color:#64748b; margin:0;">هیچ تهاجم یا تزریق کدی در بازه اخیر ثبت نشده است.</p>
                    <?php else: ?>
                        <table class="afc-table">
                            <thead><tr><th>زمان</th><th>نوع رویداد</th><th>شرح رویداد</th></tr></thead>
                            <tbody>
                                <?php foreach ( $security_logs as $lg ): ?>
                                    <tr>
                                        <td><code style="font-size:11px;"><?php echo esc_html( $lg['time'] ); ?></code></td>
                                        <td>
                                            <?php if ( 'self_healed' === $lg['type'] ): ?>
                                                <span class="afc-badge afc-badge-safe">ترمیم خودکار فایل</span>
                                            <?php else: ?>
                                                <span class="afc-badge afc-badge-danger">مسدودسازی فایروال</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo esc_html( $lg['message'] ); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>

            <!-- لاگ زنده ترمینال -->
            <div class="afc-box">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <h3 style="margin:0;"><span class="dashicons dashicons-editor-code"></span> لاگ زنده فرآیندها و جراحی فایل‌ها</h3>
                    <button id="afc-btn-clear-logs" class="button button-secondary">پاک‌کردن کنسول</button>
                </div>
                <div id="afc-terminal" class="afc-terminal">
                    <div class="afc-terminal-line system">[سیستم] ماژول امنیتی چندلایه Gravity آماده به کار است.</div>
                </div>
            </div>
        </div>

        <!-- زبانه ۶: مدیریت قرنطینه و بازگردانی (Rollback) -->
        <div id="tab-quarantine" class="afc-tab-pane">
            <div class="afc-box" style="margin-bottom:25px; border-right:4px solid #8b5cf6;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px;">
                    <div>
                        <h2 style="margin:0 0 8px 0; font-size:18px;">
                            <span class="dashicons dashicons-archive" style="color:#7c3aed;"></span>
                            مدیریت قرنطینه امن و مانیفست بازگردانی (Rollback)
                        </h2>
                        <p style="margin:0; color:#475569; font-size:13.5px; line-height:1.7;">
                            تمامی فایل‌های قبل از جراحی یا قرنطینه، به همراه هش SHA256، مسیر اصلی و مانیفست امن ذخیره می‌شوند تا در هر زمان بتوان فایل‌ها را بدون خطا به وضعیت پیشین بازگرداند.
                        </p>
                    </div>
                    <button id="afc-btn-refresh-quarantine" class="button button-secondary">
                        <span class="dashicons dashicons-update"></span> به‌روزرسانی لیست
                    </button>
                </div>
            </div>

            <div class="afc-box">
                <h3 style="margin-top:0;"><span class="dashicons dashicons-list-view"></span> فهرست موارد قرنطینه‌شده</h3>
                <div id="afc-quarantine-table-wrap">
                    <?php if ( empty( $quarantine_stats['items'] ) ): ?>
                        <p style="color:#64748b; padding:20px 0; text-align:center;">در حال حاضر هیچ فایلی در قرنطینه وجود ندارد.</p>
                    <?php else: ?>
                        <table class="afc-table" id="afc-table-quarantine">
                            <thead>
                                <tr>
                                    <th>شناسه پشتیبان</th>
                                    <th>مسیر فایل مبدأ</th>
                                    <th>زمان ثبت</th>
                                    <th>علت انتقال</th>
                                    <th>وضعیت</th>
                                    <th>عملیات</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $quarantine_stats['items'] as $q ): ?>
                                    <tr>
                                        <td><code><?php echo esc_html( $q['backup_id'] ); ?></code></td>
                                        <td><code style="font-size:11px;"><?php echo esc_html( str_replace( ABSPATH, '', $q['original_path'] ) ); ?></code></td>
                                        <td><?php echo esc_html( $q['timestamp'] ); ?></td>
                                        <td><span class="afc-badge"><?php echo esc_html( $q['operation_type'] ); ?></span></td>
                                        <td>
                                            <?php if ( ! empty( $q['is_restored'] ) ): ?>
                                                <span class="afc-badge afc-badge-safe">بازگردانی‌شده</span>
                                            <?php else: ?>
                                                <span class="afc-badge afc-badge-warning">در قرنطینه</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ( empty( $q['is_restored'] ) ): ?>
                                                <button class="button button-small afc-btn-rollback" data-backup-id="<?php echo esc_attr( $q['backup_id'] ); ?>">
                                                    <span class="dashicons dashicons-undo"></span> بازگردانی (Rollback)
                                                </button>
                                            <?php else: ?>
                                                <span style="color:#16a34a; font-size:12px;">بازیابی شده</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- زبانه ۷: پایش سطح هاست و ایجنت سرور -->
        <div id="tab-host" class="afc-tab-pane">
            <div class="afc-box" style="margin-bottom:25px; border-right:4px solid #0284c7;">
                <h2 style="margin:0 0 8px 0; font-size:18px;">
                    <span class="dashicons dashicons-networking" style="color:#0284c7;"></span>
                    پایش لایه هاست و یکپارچگی سرور (Host Security Agent)
                </h2>
                <p style="margin:0; color:#475569; font-size:13.5px; line-height:1.7;">
                    مطابق استانداردهای سازمانی، امنیت سطح هاست و فایل‌های خارج از ریشه وردپرس به یک Agent مستقل در سطح سیستم‌عامل (لینوکس) متکی است تا تفکیک دسترسی‌ها به درستی رعایت شود.
                </p>
            </div>

            <div class="afc-grid-2">
                <div class="afc-box">
                    <h3 style="margin-top:0;"><span class="dashicons dashicons-admin-site"></span> وضعیت اتصال ایجنت سروری</h3>
                    <div style="padding:15px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:15px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>وضعیت پوشش هاست:</strong>
                            <span class="afc-badge <?php echo $host_status['is_active'] ? 'afc-badge-safe' : 'afc-badge-warning'; ?>">
                                <?php echo esc_html( $host_status['label'] ); ?>
                            </span>
                        </div>
                        <p style="font-size:13px; color:#64748b; margin:10px 0 0 0; line-height:1.6;">
                            <?php echo esc_html( isset( $host_status['details'] ) ? $host_status['details'] : '' ); ?>
                        </p>
                    </div>

                    <h4>قابلیت‌های فعال:</h4>
                    <ul style="list-style:disc; padding-right:20px; font-size:13px; color:#334155; line-height:1.8;">
                        <li>امنیت در لایه برنامه وب (WAF و محافظت PHP): <strong style="color:#16a34a;">فعال</strong></li>
                        <li>جراحی و خودترمیم‌کننده کدهای وردپرس: <strong style="color:#16a34a;">فعال</strong></li>
                        <li>قفل ضد بازنویسی فایل‌ها (0444): <strong style="color:#16a34a;">فعال</strong></li>
                        <li>پایش فایل‌های خارج از ریشه وب (هاست ایجنت): 
                            <?php if ( $host_status['is_active'] ): ?>
                                <strong style="color:#16a34a;">فعال</strong>
                            <?php else: ?>
                                <strong style="color:#dc2626;">غیرفعال (نیازمند دسترسی سرور)</strong>
                            <?php endif; ?>
                        </li>
                    </ul>
                </div>

                <div class="afc-box">
                    <h3 style="margin-top:0;"><span class="dashicons dashicons-info"></span> راهنمای فعال‌سازی ایجنت مستقل سرور</h3>
                    <p style="font-size:13px; color:#475569; line-height:1.7;">
                        جهت فعال‌سازی پوشش کامل هاست و اسکن بدافزار لینوکس با <strong>LMD</strong>:
                    </p>
                    <ol style="font-size:12.5px; color:#334155; line-height:1.8; padding-right:20px;">
                        <li>اسکریپت مستقل <code>host-agent/gravity-agent.py</code> را روی سرور لینوکس مستقر کنید.</li>
                        <li>فایل پیکربندی <code>/etc/gravity-agent/config.json</code> را با کلید رمز اختصاصی ایجاد نمایید.</li>
                        <li>سرویس Systemd مربوطه را فعال کنید تا پایش بدون سربار CPU به طور مداوم اجرا گردد.</li>
                    </ol>
                    <p style="font-size:12px; color:#64748b;">
                        <em>توجه: در صورتی که از هاست اشتراکی استفاده می‌کنید، نیازی به این مرحله نیست و تمامی لایه‌های دفاعی وردپرس به طور خودکار فعال هستند.</em>
                    </p>
                </div>
            </div>
        </div>

    </div>
</div>
