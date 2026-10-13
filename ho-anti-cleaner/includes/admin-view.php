<?php
/**
 * Admin Dashboard View for AssetFlow Cleaner & Optimizer
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

$security_checks = class_exists( 'HO_Anti_Optimizer' ) ? HO_Anti_Optimizer::audit_security_health() : [];
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
                    ضد بدافزار و بهینه‌ساز HO Anti (توسعه: ho mehdi sabour)
                    <span class="afc-badge afc-badge-safe" style="font-size: 11px; margin-right: 8px; vertical-align: middle;">نسخه <?php echo esc_html( HO_ANTI_VERSION ); ?></span>
                </h1>
                <p class="afc-header-subtitle">شناسایی عمیق، جراحی و ترمیم فایل‌های آلوده، حذف درپشتی‌ها و بهینه‌سازی دیتابیس</p>
            </div>
        </div>
        <div class="afc-header-actions">
            <!-- دکمه پاک‌سازی مستقیم بدون نیاز به AJAX برای دور زدن خطای wp_die -->
            <form method="post" style="display:inline-block;" onsubmit="return confirm('آیا از اجرای پاک‌سازی و ترمیم کلیه فایل‌ها و دیتابیس اطمینان دارید؟');">
                <button type="submit" name="afc_direct_action" value="clean_all_direct" class="button button-danger afc-btn-hero">
                    <span class="dashicons dashicons-shield"></span> پاک‌سازی اضطراری و مستقیم (ضد wp_die)
                </button>
            </form>
            <button id="afc-btn-quick-scan" class="button button-primary afc-btn-hero">
                <span class="dashicons dashicons-search"></span> اسکن سیستم
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
                <span class="afc-stat-label">فایل‌های PHP آلوده</span>
                <span class="afc-stat-value" id="afc-val-files">-</span>
            </div>
        </div>
        <div class="afc-stat-card">
            <div class="afc-stat-icon dashicons dashicons-admin-plugins"></div>
            <div class="afc-stat-content">
                <span class="afc-stat-label">فایل‌های MU-Plugin</span>
                <span class="afc-stat-value" id="afc-val-mu">-</span>
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
        <a href="#tab-scan" class="afc-tab-btn active" data-tab="tab-scan">
            <span class="dashicons dashicons-visibility"></span> نتایج اسکن و تهدیدات
        </a>
        <a href="#tab-remediate" class="afc-tab-btn" data-tab="tab-remediate">
            <span class="dashicons dashicons-trash"></span> جعبه‌ابزار پاک‌سازی و جراحی
        </a>
        <a href="#tab-optimize" class="afc-tab-btn" data-tab="tab-optimize">
            <span class="dashicons dashicons-performance"></span> بهینه‌سازی دیتابیس و امنیت
        </a>
        <a href="#tab-logs" class="afc-tab-btn" data-tab="tab-logs">
            <span class="dashicons dashicons-editor-code"></span> گزارش و لاگ زنده
        </a>
    </div>

    <!-- محتوای زبانه‌ها -->
    <div class="afc-tab-content-wrapper">

        <!-- زبانه ۱: اسکن و جزئیات یافته‌ها -->
        <div id="tab-scan" class="afc-tab-pane active">
            <div id="afc-empty-state" class="afc-box afc-empty-state">
                <div class="dashicons dashicons-shield-alt afc-empty-icon"></div>
                <h2>اسکن هوشمند فایل‌ها و پایگاه داده</h2>
                <p>جهت بررسی دیتابیس، فایل‌های هسته، پوشه wp-content و پیدا کردن ردپای بدافزار Asset Flow، روی دکمه زیر کلیک کنید.</p>
                <button class="button button-primary afc-btn-start-scan">شروع اسکن</button>
            </div>

            <div id="afc-scan-results" style="display:none;">
                <!-- ۱. کاربران مخفی -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-admin-users"></span> کاربران مخفی با دسترسی مدیر (Hidden Admins)</h3>
                        <span id="afc-badge-users" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-users" class="afc-section-body"></div>
                </div>

                <!-- ۲. جداول و آپشن‌های دیتابیس -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-database"></span> جداول و تنظیمات تزریق‌شده در دیتابیس</h3>
                        <span id="afc-badge-db" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-db" class="afc-section-body"></div>
                </div>

                <!-- ۳. فایل‌های mu-plugins -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-admin-plugins"></span> فایل‌های خوداجرا در پوشه mu-plugins</h3>
                        <span id="afc-badge-mu" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-mu" class="afc-section-body"></div>
                </div>

                <!-- ۴. فایل‌های PHP آلوده -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-media-code"></span> فایل‌های PHP آلوده شده در سیستم</h3>
                        <span id="afc-badge-files" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-files" class="afc-section-body"></div>
                </div>

                <!-- ۵. فایل‌های مشکوک در آپلودها -->
                <div class="afc-section-box">
                    <div class="afc-section-header">
                        <h3><span class="dashicons dashicons-upload"></span> فایل‌های PHP غیرمجاز در پوشه Uploads</h3>
                        <span id="afc-badge-uploads" class="afc-badge afc-badge-safe">پاک</span>
                    </div>
                    <div id="afc-list-uploads" class="afc-section-body"></div>
                </div>
            </div>
        </div>

        <!-- زبانه ۲: ابزار پاک‌سازی و ترمیم دستی/خودکار -->
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
                    <p>کدهای مخرب تزریق‌شده به انتهای فایل‌های PHP را با دقت حذف کرده و فایل را به وضعیت سالم بازمی‌گرداند. یک نسخه بک‌آپ در قرنطینه ذخیره می‌شود.</p>
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

        <!-- زبانه ۳: بهینه‌سازی دیتابیس و امنیت -->
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
                <p>بدافزار Asset Flow از مقدار <code>AUTH_SALT</code> سایت شما برای ساخت رمزهای درپشتی استفاده می‌کرد. حتماً پس از پاک‌سازی، کلیدهای امنیتی زیر را کپی کرده و در فایل <code>wp-config.php</code> جایگزین کنید تا همه نشست‌های باز باطل شوند:</p>
                <button id="afc-btn-get-salts" class="button button-secondary" style="margin-bottom: 10px;">
                    تولید کلیدهای جدید تصادفی
                </button>
                <div id="afc-salts-container" style="display:none;">
                    <textarea id="afc-salts-text" readonly rows="9" style="width:100%; direction:ltr; font-family:monospace; font-size:12px; background:#f9f9f9;"></textarea>
                    <button id="afc-copy-salts" class="button button-primary" style="margin-top:5px;">کپی در کلیپ‌بورد</button>
                </div>
            </div>
        </div>

        <!-- زبانه ۴: لاگ زنده و تاریخچه -->
        <div id="tab-logs" class="afc-tab-pane">
            <div class="afc-box">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <h3 style="margin:0;"><span class="dashicons dashicons-editor-code"></span> لاگ زنده فرآیندها و جراحی فایل‌ها</h3>
                    <button id="afc-btn-clear-logs" class="button button-secondary">پاک‌کردن کنسول</button>
                </div>
                <div id="afc-terminal" class="afc-terminal">
                    <div class="afc-terminal-line system">[سیستم] ماژول ضد بدافزار آماده به کار است.</div>
                </div>
            </div>
        </div>

    </div>
</div>
