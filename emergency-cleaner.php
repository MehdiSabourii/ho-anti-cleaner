<?php
/**
 * Emergency Standalone HO Anti Cleaner & Security Shield v3.0.0
 * فایل اضطراری تک‌مرحله‌ای برای پاک‌سازی کامل سایت، جراحی گیت‌کیپرهای لاگین و قفل محافظتی فایل‌ها
 * نحوه استفاده: این فایل را در ریشه وردپرس (کنار wp-config.php) آپلود کرده و در مرورگر باز کنید.
 */

// جلوگیری از کش مرورگر
header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
header( 'Content-Type: text/html; charset=utf-8' );

// افزایش منابع سرور
@ini_set( 'memory_limit', '512M' );
@set_time_limit( 300 );

// یافتن و بارگذاری وردپرس
$wp_load_path = __DIR__ . '/wp-load.php';
if ( ! file_exists( $wp_load_path ) && file_exists( dirname( __DIR__ ) . '/wp-load.php' ) ) {
    $wp_load_path = dirname( __DIR__ ) . '/wp-load.php';
}

if ( ! file_exists( $wp_load_path ) ) {
    die( '<div style="font-family:tahoma; padding:20px; color:red; direction:rtl;">خطا: فایل wp-load.php یافت نشد. لطفاً این فایل را در پوشه اصلی سایت (کنار wp-config.php) قرار دهید.</div>' );
}

require_once $wp_load_path;

global $wpdb;

$actions_log = [];
$is_executed = false;

// تابع کمکی جراحی فایل‌ها
function ho_emergency_repair_file( $path, &$actions_log ) {
    if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
        return false;
    }

    $was_locked = ! is_writable( $path );
    if ( $was_locked ) {
        @chmod( $path, 0644 );
    }

    $content = @file_get_contents( $path );
    if ( empty( $content ) ) {
        if ( $was_locked ) @chmod( $path, 0444 );
        return false;
    }

    $modified = false;
    $new_content = $content;

    // ۱. جراحی کدهای مسدودکننده در بالای فایل (Header Gatekeeper)
    $header_patterns = [
        '/<\?php\s*while\s*\(\s*md5\s*\(\s*md5\s*\(.+?die\s*\(\s*\)\s*;?\s*\}?/is',
        '/<\?php\s*while\s*\([^;]*yrxc_u[^;]*;?\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
        '/<\?php\s*(?:while|if)\s*\([^)]*md5[^)]*\)\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
    ];

    foreach ( $header_patterns as $pat ) {
        if ( preg_match( $pat, $new_content ) ) {
            $new_content = preg_replace( $pat, "<?php\n", $new_content, 1 );
            $modified = true;
            $actions_log[] = [ 'type' => 'success', 'msg' => 'جراحی هدر و حذف گیت‌کیپر ورود از فایل: ' . str_replace( ABSPATH, '', $path ) ];
            break;
        }
    }

    // ۲. جراحی کدهای بدافزار در انتهای فایل (Bottom Asset Flow)
    $markers = [
        '/* Plugin Name: Asset Flow',
        'Plugin Name: Asset Flow',
        'goto xCzpFLgFPHRLRAiM;',
        'class WP_Sys_Optimiser',
        'AV_COMPLETED',
    ];

    $earliest_pos = false;
    foreach ( $markers as $marker ) {
        $pos = strpos( $new_content, $marker );
        if ( false !== $pos ) {
            if ( false === $earliest_pos || $pos < $earliest_pos ) {
                $earliest_pos = $pos;
            }
        }
    }

    if ( false !== $earliest_pos ) {
        if ( $earliest_pos < 300 && false !== strpos( $new_content, 'Plugin Name: Asset Flow' ) ) {
            @unlink( $path );
            $actions_log[] = [ 'type' => 'success', 'msg' => 'حذف فایل مستقل بدافزار: ' . str_replace( ABSPATH, '', $path ) ];
            return true;
        }

        $new_content = substr( $new_content, 0, $earliest_pos );
        $new_content = preg_replace( '/\?>\s*<\?php\s*$/', '', $new_content );
        $new_content = preg_replace( '/\?>\s*$/', '', $new_content );
        $new_content = rtrim( $new_content ) . "\n";
        $modified = true;
        $actions_log[] = [ 'type' => 'success', 'msg' => 'جراحی انتهای فایل و حذف کدهای Asset Flow: ' . str_replace( ABSPATH, '', $path ) ];
    }

    if ( $modified ) {
        @file_put_contents( $path, $new_content );
        @chmod( $path, 0444 ); // قفل کردن مجدد جهت جلوگیری از آلودگی دوباره
        return true;
    }

    if ( $was_locked ) {
        @chmod( $path, 0444 );
    }

    return false;
}

// اجرای عملیات
if ( isset( $_POST['run_emergency_clean'] ) || isset( $_GET['run'] ) ) {
    $is_executed = true;

    // ۱. پاک‌سازی درپشتی‌های mu-plugins
    $mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
    if ( is_dir( $mu_dir ) ) {
        $mu_all_files = glob( $mu_dir . '/*.php' );
        if ( ! empty( $mu_all_files ) ) {
            foreach ( $mu_all_files as $f ) {
                $c = @file_get_contents( $f );
                if ( false !== strpos( $f, '01-mu-' ) || false !== stripos( $c, 'Asset Flow' ) || false !== strpos( $c, 'WP_Sys_Optimiser' ) || false !== strpos( $c, 'xCzpFLgFPHRLRAiM' ) || false !== strpos( $c, 'yrxc_u' ) ) {
                    if ( @unlink( $f ) ) {
                        $actions_log[] = [ 'type' => 'success', 'msg' => 'فایل درپشتی mu-plugin حذف شد: ' . basename( $f ) ];
                    }
                }
            }
        }
    }

    // ۲. حذف کاربران مخفی sys_*
    $users = $wpdb->get_results( "SELECT ID, user_login FROM {$wpdb->users} WHERE user_login LIKE 'sys_%'" );
    $u_count = 0;
    foreach ( $users as $u ) {
        $wpdb->delete( $wpdb->users, [ 'ID' => $u->ID ] );
        $wpdb->delete( $wpdb->usermeta, [ 'user_id' => $u->ID ] );
        $u_count++;
    }
    if ( $u_count > 0 ) {
        $actions_log[] = [ 'type' => 'success', 'msg' => "تعداد $u_count کاربر مخفی درپشتی (sys_*) از دیتابیس پاک شدند." ];
    }

    // ۳. حذف آپشن‌های مخرب
    $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name IN ('jsonmetafield', 'sub_valid_adm', 'sub_valid_adm1')" );
    $actions_log[] = [ 'type' => 'success', 'msg' => 'کلیدهای jsonmetafield و sub_valid_adm از wp_options حذف شدند.' ];

    // ۴. حذف جداول wp_sys_av_*
    $tables = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}sys_av_%'" );
    foreach ( $tables as $tbl ) {
        $wpdb->query( "DROP TABLE IF EXISTS `$tbl`" );
        $actions_log[] = [ 'type' => 'success', 'msg' => "جدول مخرب `$tbl` از دیتابیس حذف شد." ];
    }

    // ۵. بررسی و جراحی کلیه فایل‌های PHP ریشه وردپرس (از جمله wp-login.php، index.php و...)
    $root_php_files = glob( ABSPATH . '*.php' );
    if ( ! empty( $root_php_files ) ) {
        foreach ( $root_php_files as $r_file ) {
            ho_emergency_repair_file( $r_file, $actions_log );
        }
    }

    // ۶. اسکن و جراحی بازگشتی در پوشه wp-content
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator( WP_CONTENT_DIR, RecursiveDirectoryIterator::SKIP_DOTS )
    );

    foreach ( $iterator as $file ) {
        if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
            $path = $file->getRealPath();
            if ( $path === __FILE__ ) continue;
            ho_emergency_repair_file( $path, $actions_log );
        }
    }

    // ۷. استقرار سپر محافظتی در uploads
    $upload_dir = wp_upload_dir();
    $ht_upload = $upload_dir['basedir'] . '/.htaccess';
    $ht_rules = "# HO Anti Security Shield\n<FilesMatch \"(?i)\\.(php|php[0-9]?|phtml|phar|pl|py|cgi|asp|aspx|sh|exe)$\">\n    Order Deny,Allow\n    Deny from all\n</FilesMatch>\n";
    @file_put_contents( $ht_upload, $ht_rules );
    @chmod( $ht_upload, 0444 );
    $actions_log[] = [ 'type' => 'success', 'msg' => 'سپر محافظتی htaccess در پوشه uploads مستقر شد.' ];

    // ۸. قفل کردن فایل‌های حیاتی به 0444 (ضد بازنویسی)
    $crit_files = [ ABSPATH . 'wp-login.php', ABSPATH . 'index.php', ABSPATH . 'wp-settings.php', ABSPATH . 'wp-load.php' ];
    foreach ( $crit_files as $cf ) {
        if ( file_exists( $cf ) ) {
            @chmod( $cf, 0444 );
        }
    }
    $actions_log[] = [ 'type' => 'success', 'msg' => 'فایل‌های حساس هسته وردپرس با مجوز 0444 قفل شدند (ضد تزریق مجدد).' ];

    wp_cache_flush();
}

// دکمه قفل دستی فایل‌ها
if ( isset( $_POST['lock_files_only'] ) ) {
    $crit_files = [ ABSPATH . 'wp-login.php', ABSPATH . 'index.php', ABSPATH . 'wp-config.php', ABSPATH . 'wp-settings.php', ABSPATH . 'wp-load.php' ];
    foreach ( $crit_files as $cf ) {
        if ( file_exists( $cf ) ) {
            @chmod( $cf, 0444 );
        }
    }
    $actions_log[] = [ 'type' => 'success', 'msg' => 'کلیه فایل‌های حساس به 0444 قفل شدند.' ];
    $is_executed = true;
}

// حذف خودکار این فایل پس از اتمام کار
if ( isset( $_POST['self_delete'] ) ) {
    @unlink( __FILE__ );
    die( '<div style="font-family:tahoma; padding:30px; direction:rtl; color:green; text-align:center;"><h2>این فایل اضطراری با موفقیت از روی هاست حذف شد.</h2><p><a href="' . home_url( '/wp-login.php' ) . '">ورود به صفحه لاگین وردپرس</a></p></div>' );
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ابزار اضطراری HO Anti v3.0.0</title>
    <style>
        body { font-family: -apple-system, Tahoma, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 40px 20px; color: #1e293b; }
        .container { max-width: 860px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); padding: 32px; }
        h1 { margin-top: 0; color: #0f172a; font-size: 22px; border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; }
        p { line-height: 1.7; font-size: 14px; color: #475569; }
        .btn { display: inline-block; padding: 12px 24px; font-size: 14px; font-weight: bold; border-radius: 8px; cursor: pointer; border: none; text-decoration: none; }
        .btn-danger { background: #dc2626; color: #fff; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-success { background: #16a34a; color: #fff; }
        .btn-secondary { background: #64748b; color: #fff; }
        .log-box { background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 18px; margin-top: 24px; font-family: monospace; font-size: 13px; max-height: 420px; overflow-y: auto; direction: ltr; text-align: left; }
        .log-item { margin-bottom: 6px; }
        .log-success { color: #4ade80; }
        .alert-done { background: #dcfce7; border: 1px solid #86efac; color: #15803d; padding: 16px; border-radius: 8px; margin-top: 20px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ پاک‌ساز اضطراری و سپر ضد تزریق HO Anti v3.0.0</h1>
    <p>این ابزار به صورت مستقیم فایل‌های ریشه (به ویژه <code>wp-login.php</code>) را از گیت‌کیپرهای مسدودکننده پاک کرده، فایل‌های آلوده به بدافزار را جراحی و کلیه درپشتی‌های دیتابیس و mu-plugins را حذف نموده و فایل‌های حساس را با مجوز 0444 قفل می‌کند.</p>

    <?php if ( ! $is_executed ): ?>
        <form method="post" style="display:flex; gap:12px;">
            <button type="submit" name="run_emergency_clean" value="1" class="btn btn-danger">
                شروع عملیات پاک‌سازی کامل و جراحی فایل‌ها
            </button>
            <button type="submit" name="lock_files_only" value="1" class="btn btn-success">
                فقط قفل کردن فایل‌های حساس (0444)
            </button>
        </form>
    <?php else: ?>
        <div class="alert-done">
            <strong>✅ عملیات پاک‌سازی و محافظت کامل شد!</strong> گزارش اقدامات انجام شده در کادر زیر ثبت گردید.
        </div>

        <div class="log-box">
            <?php foreach ( $actions_log as $log ): ?>
                <div class="log-item log-success">[DONE] <?php echo esc_html( $log['msg'] ); ?></div>
            <?php endforeach; ?>
            <?php if ( empty( $actions_log ) ): ?>
                <div class="log-item">[INFO] موردی از بدافزار یافت نشد یا سایت از قبل پاک بوده است.</div>
            <?php endif; ?>
        </div>

        <div style="margin-top: 25px; display: flex; gap: 12px; flex-wrap:wrap;">
            <a href="<?php echo esc_url( home_url( '/wp-login.php' ) ); ?>" class="btn btn-success">ورود به صفحه لاگین (wp-login.php)</a>
            <a href="<?php echo esc_url( admin_url() ); ?>" class="btn btn-secondary">ورود به پیشخوان وردپرس</a>
            <form method="post">
                <button type="submit" name="self_delete" value="1" class="btn btn-danger" onclick="return confirm('آیا از حذف این فایل اضطراری مطمئن هستید؟');">
                    حذف خودکار این فایل اضطراری از هاست
                </button>
            </form>
        </div>
    <?php endif; ?>
</div>
</body>
</html>
