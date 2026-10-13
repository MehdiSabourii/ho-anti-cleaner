<?php
/**
 * Emergency Standalone AssetFlow Cleaner & Disinfector
 * فایل اضطراری تک‌مرحله‌ای برای پاک‌سازی کامل سایت در شرایط قطع دسترسی به پیشخوان یا خطای wp_die
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

// اجرای خودکار یا با ارسال فرم
if ( isset( $_POST['run_emergency_clean'] ) || isset( $_GET['run'] ) ) {
    $is_executed = true;

    // ۱. پاک‌سازی عمیق فایل‌های mu-plugins
    $mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
    if ( is_dir( $mu_dir ) ) {
        $mu_all_files = glob( $mu_dir . '/*.php' );
        if ( ! empty( $mu_all_files ) ) {
            foreach ( $mu_all_files as $f ) {
                $c = @file_get_contents( $f );
                if ( false !== strpos( $f, '01-mu-' ) || false !== stripos( $c, 'Asset Flow' ) || false !== strpos( $c, 'WP_Sys_Optimiser' ) || false !== strpos( $c, 'xCzpFLgFPHRLRAiM' ) ) {
                    if ( @unlink( $f ) ) {
                        $actions_log[] = [ 'type' => 'success', 'msg' => 'فایل درپشتی mu-plugin شناسایی و حذف شد: ' . basename( $f ) ];
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

    // ۵. اسکن و جراحی فایل‌های آلوده در wp-content
    $markers = [
        '/* Plugin Name: Asset Flow',
        'Plugin Name: Asset Flow',
        'goto xCzpFLgFPHRLRAiM;',
        'class WP_Sys_Optimiser',
        'AV_COMPLETED',
    ];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator( WP_CONTENT_DIR, RecursiveDirectoryIterator::SKIP_DOTS )
    );

    $repaired_files = 0;
    $deleted_malware = 0;

    foreach ( $iterator as $file ) {
        if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
            $path = $file->getRealPath();
            if ( $path === __FILE__ ) continue;

            $content = @file_get_contents( $path );
            if ( ! $content ) continue;

            $earliest_pos = false;
            foreach ( $markers as $marker ) {
                $pos = strpos( $content, $marker );
                if ( false !== $pos ) {
                    if ( false === $earliest_pos || $pos < $earliest_pos ) {
                        $earliest_pos = $pos;
                    }
                }
            }

            if ( false !== $earliest_pos ) {
                // اگر فایل مستقل بدافزار است
                if ( $earliest_pos < 300 && false !== strpos( $content, 'Plugin Name: Asset Flow' ) ) {
                    @unlink( $path );
                    $deleted_malware++;
                    $actions_log[] = [ 'type' => 'success', 'msg' => 'حذف فایل کامل بدافزار: ' . str_replace( ABSPATH, '', $path ) ];
                    continue;
                }

                // برش بخش تزریقی و نجات فایل مجاز
                $clean_code = substr( $content, 0, $earliest_pos );
                $clean_code = preg_replace( '/\?>\s*<\?php\s*$/', '', $clean_code );
                $clean_code = preg_replace( '/\?>\s*$/', '', $clean_code );
                $clean_code = rtrim( $clean_code ) . "\n";

                if ( false !== @file_put_contents( $path, $clean_code ) ) {
                    $repaired_files++;
                    $actions_log[] = [ 'type' => 'success', 'msg' => 'ترمیم و جراحی فایل: ' . str_replace( ABSPATH, '', $path ) ];
                }
            }
        }
    }

    // پاک‌سازی کش آبجکت
    wp_cache_flush();
}

// دکمه حذف خودکار این فایل پس از اتمام کار
if ( isset( $_POST['self_delete'] ) ) {
    @unlink( __FILE__ );
    die( '<div style="font-family:tahoma; padding:30px; direction:rtl; color:green; text-align:center;"><h2>این فایل اضطراری با موفقیت از روی هاست حذف شد.</h2><p><a href="' . home_url( '/wp-admin/' ) . '">ورود به پیشخوان وردپرس</a></p></div>' );
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ابزار اضطراری پاک‌سازی بدافزار AssetFlow</title>
    <style>
        body { font-family: -apple-system, Tahoma, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 40px 20px; color: #1e293b; }
        .container { max-width: 820px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); padding: 32px; }
        h1 { margin-top: 0; color: #0f172a; font-size: 22px; border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; }
        p { line-height: 1.7; font-size: 14px; color: #475569; }
        .btn { display: inline-block; padding: 12px 24px; font-size: 14px; font-weight: bold; border-radius: 8px; cursor: pointer; border: none; text-decoration: none; }
        .btn-danger { background: #dc2626; color: #fff; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-secondary { background: #64748b; color: #fff; }
        .log-box { background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 18px; margin-top: 24px; font-family: monospace; font-size: 13px; max-height: 420px; overflow-y: auto; direction: ltr; text-align: left; }
        .log-item { margin-bottom: 6px; }
        .log-success { color: #4ade80; }
        .alert-done { background: #dcfce7; border: 1px solid #86efac; color: #15803d; padding: 16px; border-radius: 8px; margin-top: 20px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ پاک‌ساز اضطراری بدافزار AssetFlow (مستقل از پیشخوان)</h1>
    <p>این اسکریپت اضطراری به صورت مستقیم و بدون وابستگی به توابع AJAX یا افزونه‌های دیگر اجرا می‌شود و کلیه ردپاهای بدافزار (کاربران مخفی، جداول دیتابیس، درپشتی‌های mu-plugins و کدهای تزریق‌شده در فایل‌های PHP) را به طور کامل پاک و جراحی می‌کند.</p>

    <?php if ( ! $is_executed ): ?>
        <form method="post">
            <button type="submit" name="run_emergency_clean" value="1" class="btn btn-danger">
                شروع عملیات پاک‌سازی و جراحی اضطراری سایت
            </button>
        </form>
    <?php else: ?>
        <div class="alert-done">
            <strong>✅ عملیات پاک‌سازی کامل شد!</strong> گزارش کارهای انجام شده در کادر زیر ثبت گردید.
        </div>

        <div class="log-box">
            <?php foreach ( $actions_log as $log ): ?>
                <div class="log-item log-success">[DONE] <?php echo esc_html( $log['msg'] ); ?></div>
            <?php endforeach; ?>
            <?php if ( empty( $actions_log ) ): ?>
                <div class="log-item">[INFO] موردی از بدافزار یافت نشد یا سایت از قبل پاک بوده است.</div>
            <?php endif; ?>
        </div>

        <div style="margin-top: 25px; display: flex; gap: 12px;">
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
