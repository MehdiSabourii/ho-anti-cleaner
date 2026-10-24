<?php
/**
 * Automated Acceptance & Production-Readiness Test Suite for Gravity Security
 * مجموعه آزمون‌های واقعی، مثبت، منفی و اعتبارسنجی اصلاح و بازگردانی
 */

error_reporting( E_ALL );
ini_set( 'display_errors', '1' );

echo "========================================================\n";
echo "GRAVITY SECURITY TEST SUITE — PRODUCTION READINESS AUDIT\n";
echo "========================================================\n\n";

// ۱. راه‌اندازی محیط شبیه‌سازی ایزوله سندباکس
$sandbox_dir = str_replace( '\\', '/', __DIR__ . '/fixtures/sandbox' );
if ( ! is_dir( $sandbox_dir ) ) {
    mkdir( $sandbox_dir, 0777, true );
}

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', $sandbox_dir . '/' );
}
if ( ! defined( 'WP_CONTENT_DIR' ) ) {
    define( 'WP_CONTENT_DIR', $sandbox_dir . '/wp-content' );
}
if ( ! defined( 'WPMU_PLUGIN_DIR' ) ) {
    define( 'WPMU_PLUGIN_DIR', WP_CONTENT_DIR . '/mu-plugins' );
}
if ( ! defined( 'HO_ANTI_VERSION' ) ) {
    define( 'HO_ANTI_VERSION', '3.0.0' );
}
if ( ! defined( 'HO_ANTI_PLUGIN_DIR' ) ) {
    define( 'HO_ANTI_PLUGIN_DIR', dirname( __DIR__ ) . '/ho-anti-cleaner/' );
}

// ساخت دایرکتوری‌های استاندارد سندباکس و پاک‌سازی فایل‌های قفل‌شده قبلی
@mkdir( WP_CONTENT_DIR, 0777, true );
@mkdir( WPMU_PLUGIN_DIR, 0777, true );
@mkdir( WP_CONTENT_DIR . '/uploads', 0777, true );

foreach ( (array) glob( $sandbox_dir . '/*.php' ) as $existing_f ) {
    if ( file_exists( $existing_f ) ) {
        @chmod( $existing_f, 0666 );
        @unlink( $existing_f );
    }
}

// شبیه‌سازی توابع هسته وردپرس در محیط ایزوله
$GLOBALS['mock_options']    = [];
$GLOBALS['mock_transients'] = [];

function wp_normalize_path( $path ) {
    $path = str_replace( '\\', '/', $path );
    return preg_replace( '|(?<=.)/+|', '/', $path );
}
function current_time( $type ) {
    return date( 'Y-m-d H:i:s' );
}
function sanitize_file_name( $name ) {
    return preg_replace( '/[^a-zA-Z0-9_\.-]/', '_', $name );
}
function wp_mkdir_p( $target ) {
    return is_dir( $target ) || @mkdir( $target, 0777, true );
}
function wp_upload_dir() {
    return [ 'basedir' => WP_CONTENT_DIR . '/uploads' ];
}
function get_option( $name, $default = false ) {
    return isset( $GLOBALS['mock_options'][ $name ] ) ? $GLOBALS['mock_options'][ $name ] : $default;
}
function update_option( $name, $value, $autoload = false ) {
    $GLOBALS['mock_options'][ $name ] = $value;
    return true;
}
function delete_option( $name ) {
    unset( $GLOBALS['mock_options'][ $name ] );
    return true;
}
function get_transient( $name ) {
    return isset( $GLOBALS['mock_transients'][ $name ] ) ? $GLOBALS['mock_transients'][ $name ] : false;
}
function set_transient( $name, $val, $exp = 0 ) {
    $GLOBALS['mock_transients'][ $name ] = $val;
    return true;
}
function esc_html( $s ) { return htmlspecialchars( $s, ENT_QUOTES, 'UTF-8' ); }
function get_bloginfo( $show ) { return '6.6.2'; }
function _get_cron_array() {
    return [
        time() + 3600 => [
            'sys_av_auto_reinfect' => [ 'schedule' => 'hourly' ],
            'wp_normal_cron'       => [ 'schedule' => 'daily' ],
        ]
    ];
}
function wp_clear_scheduled_hook( $hook ) { return true; }
function has_action( $hook ) { return 'wp_normal_cron' === $hook; }
function get_core_updates() { return []; }
function get_site_transient( $key ) { return false; }
function get_stylesheet_directory() { return WP_CONTENT_DIR . '/themes/active-theme'; }
if ( ! function_exists( 'is_admin' ) ) { function is_admin() { return false; } }
if ( ! function_exists( 'wp_next_scheduled' ) ) { function wp_next_scheduled( $hook ) { return false; } }
if ( ! function_exists( 'wp_schedule_event' ) ) { function wp_schedule_event( $timestamp, $recurrence, $hook ) { return true; } }
if ( ! function_exists( 'add_action' ) ) { function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) { return true; } }
if ( ! function_exists( 'add_filter' ) ) { function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) { return true; } }
if ( ! function_exists( 'esc_url_raw' ) ) { function esc_url_raw( $url ) { return $url; } }
if ( ! function_exists( 'sanitize_text_field' ) ) { function sanitize_text_field( $str ) { return trim( strip_tags( $str ) ); } }

// بارگذاری کلاس‌های افزونه
require_once HO_ANTI_PLUGIN_DIR . 'includes/models/class-finding.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/contracts/interface-detection-adapter.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/remediation/class-quarantine-manager.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/remediation/class-safe-repair.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-file-integrity-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-malware-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-persistence-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-vulnerability-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/scanner/class-batch-scanner.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/host-agent/class-host-agent-bridge.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/rules/class-rule-manager.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-cleaner.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-protection.php';

// شمارنده‌های آزمون‌ها
$tests_run    = 0;
$tests_passed = 0;
$tests_failed = 0;

function assert_test( $name, $condition, $details = '' ) {
    global $tests_run, $tests_passed, $tests_failed;
    $tests_run++;
    if ( $condition ) {
        $tests_passed++;
        echo "  [PASS] $name\n";
    } else {
        $tests_failed++;
        echo "  [FAIL] $name: $details\n";
    }
}

// ==========================================
// بخش اول: سناریوهای مثبت (Positive Tests)
// ==========================================
echo "\n--- 1. سناریوهای مثبت (Positive Detection Tests) ---\n";

// ۱.۱: تشخیص وب‌شل WSO
$wso_file = $sandbox_dir . '/wso_shell.php';
file_put_contents( $wso_file, "<?php \$wso_version = '2.5'; default_use_auth(); // WSO Web Shell" );
$mal_engine = new HO_Anti_Malware_Engine();
$wso_findings = $mal_engine->scan( [ $wso_file ] );
assert_test(
    'تشخیص قطعی وب‌شل WSO با شناسه MAL_SHELL_WSO',
    ! empty( $wso_findings ) && 'MAL_SHELL_WSO' === $wso_findings[0]->rule_id,
    'یافته‌ای برای وب‌شل WSO ثبت نشد.'
);

// ۱.۲: تشخیص وب‌شل با زنجیره eval + base64 + gzinflate
$eval_file = $sandbox_dir . '/eval_decoder.php';
file_put_contents( $eval_file, "<?php \$raw = '...'; eval(gzinflate(base64_decode(\$raw)));" );
$eval_findings = $mal_engine->scan( [ $eval_file ] );
assert_test(
    'تشخیص زنجیره خطرناک eval(gzinflate(base64_decode)) توسط تحلیلگر معنایی توکن‌ها',
    ! empty( $eval_findings ) && 'AST_EVAL_DECODER_CHAIN' === $eval_findings[0]->rule_id,
    'زنجیره دکودر توسط موتور استاتیک کشف نشد.'
);

// ۱.۳: تشخیص درپشتی بدافزار Asset Flow
$asset_file = $sandbox_dir . '/asset_flow_test.php';
file_put_contents( $asset_file, "<?php class WP_Sys_Optimiser { const AV_COMPLETED = 1; goto xCzpFLgFPHRLRAiM; }" );
$asset_findings = $mal_engine->scan( [ $asset_file ] );
assert_test(
    'تشخیص امضای انحصاری Asset Flow / WP_Sys_Optimiser',
    ! empty( $asset_findings ) && 'MAL_WP_ASSET_FLOW' === $asset_findings[0]->rule_id
);

// ۱.۴: تشخیص نقطه ماندگاری در mu-plugins
$mu_test_file = WPMU_PLUGIN_DIR . '/01-mu-loader.php';
file_put_contents( $mu_test_file, "<?php // backdoor loader\nclass WP_Sys_Optimiser {}" );
$pers_engine = new HO_Anti_Persistence_Engine();
$pers_findings = $pers_engine->scan();
$found_mu = false;
foreach ( $pers_findings as $f ) {
    if ( 'MU_PLUGIN_BACKDOOR' === $f->rule_id ) $found_mu = true;
}
assert_test( 'تشخیص درپشتی خوداجرا در پوشه mu-plugins', $found_mu );

// ۱.۵: تشخیص هوک مخرب در WP-Cron
$found_cron = false;
foreach ( $pers_findings as $f ) {
    if ( 'CRON_SUSPICIOUS_HOOK' === $f->rule_id && 'sys_av_auto_reinfect' === $f->target_path ) {
        $found_cron = true;
    }
}
assert_test( 'تشخیص کران‌جاب مشکوک به بدافزار (sys_av_auto_reinfect)', $found_cron );


// ==========================================
// بخش دوم: سناریوهای منفی (Negative Tests / Zero False Positives)
// ==========================================
echo "\n--- 2. سناریوهای منفی (False Positive Resistance Tests) ---\n";

// ۲.۱: افزونه سالم که از base64_decode برای بارگذاری تصویر یا کانفیگ استفاده می‌کند
$benign_base64_file = $sandbox_dir . '/benign_image_loader.php';
file_put_contents( $benign_base64_file, "<?php\n\$icon = base64_decode('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAA');\nheader('Content-Type: image/png');\necho \$icon;" );
$benign_findings = $mal_engine->scan( [ $benign_base64_file ] );
assert_test(
    'عدم اعلام هشدار کاذب برای فایل سالمی که از base64_decode برای تصویر استفاده می‌کند',
    empty( $benign_findings ),
    'فایل سالم به اشتباه بدافزار تشخیص داده شد!'
);

// ۲.۲: فایل index.php محافظ پوشه رسانه‌ها
$upload_index = WP_CONTENT_DIR . '/uploads/index.php';
file_put_contents( $upload_index, "<?php\n// Silence is golden.\n" );
$clean_res = HO_Anti_Cleaner::clean_uploads_php();
assert_test(
    'جلوگیری از حذف فایل محافظ index.php در آپلودها توسط clean_uploads_php',
    file_exists( $upload_index ),
    'فایل سالم index.php حذف شد!'
);

// ۲.۳: اعلام شفاف عدم دسترسی ایجنت هاست در محیط‌های فاقد سرور لینوکس
$host_stat = HO_Anti_Host_Agent_Bridge::get_agent_status();
assert_test(
    'اعلام شفاف وضعیت هاست ایجنت (عدم ادعای پوشش هاست بدون زیرساخت)',
    false === $host_stat['is_active'] && HO_Anti_Host_Agent_Bridge::STATUS_REQUIRES_SERVER_ACC === $host_stat['status']
);


// ==========================================
// بخش سوم: سناریوهای اصلاح، قرنطینه و Rollback
// ==========================================
echo "\n--- 3. سناریوهای جراحی امن، قرنطینه و بازگردانی (Rollback Tests) ---\n";

// ۳.۱: جراحی کدهای تزریقی گیت‌کیپر ورود به همراه اعتبارسنجی نحوی
$infected_target = $sandbox_dir . '/wp-login.php';
$clean_header_code = "<?php\nrequire_once __DIR__ . '/wp-load.php';\necho 'Login Form';\n";
$injected_header_code = "<?php while(md5(md5(isset(\$_COOKIE[\"yrxc_u\"])))){die();} ?><?php\nrequire_once __DIR__ . '/wp-load.php';\necho 'Login Form';\n";
file_put_contents( $infected_target, $injected_header_code );

$repair_res = HO_Anti_Safe_Repair::targeted_surgical_repair( $infected_target );
assert_test(
    'موفقیت در جراحی کد مسدودکننده لاگین بدون آسیب به سورس اصلی',
    ! empty( $repair_res['success'] ) && 'targeted_surgical_repair' === $repair_res['action']
);

$syntax_check = HO_Anti_Safe_Repair::validate_php_syntax( file_get_contents( $infected_target ) );
assert_test(
    'اعتبارسنجی نحوی: فایل جراحی‌شده فاقد خطای گرامری PHP است',
    $syntax_check['valid']
);

// ۳.۲: بررسی وجود بسته قرنطینه در مانیفست
$backup_id = $repair_res['backup_id'];
$manifest  = HO_Anti_Quarantine_Manager::get_manifest();
assert_test(
    'ثبت موفق نسخه پیش از جراحی در مانیفست متادیتای قرنطینه',
    isset( $manifest[ $backup_id ] ) && $manifest[ $backup_id ]['original_path'] === wp_normalize_path( $infected_target )
);

// ۳.۳: تست بازگردانی خودکار (Rollback) از قرنطینه
$rollback_res = HO_Anti_Quarantine_Manager::rollback( $backup_id );
assert_test(
    'بازگردانی موفق و کامل فایل از قرنطینه (Rollback)',
    ! empty( $rollback_res['success'] )
);

$restored_content = file_get_contents( $infected_target );
assert_test(
    'تطبیق بایت‌به‌بایت فایل بازیابی‌شده با نسخه قبل از جراحی',
    $restored_content === $injected_header_code
);

// ۳.۴: پیشگیری از تخریب سایت در صورت خطای نحوی (Syntax Guard)
$corrupt_code = "<?php function broken_syntax( { echo 'Unbalanced';";
$syntax_fail_check = HO_Anti_Safe_Repair::validate_php_syntax( $corrupt_code );
assert_test(
    'نگهبان نحوی (Syntax Guard): مهار کدهای دارای عدم تراز آکولاد یا سینتکس خراب',
    false === $syntax_fail_check['valid']
);


// ==========================================
// بخش چهارم: تست هماهنگ‌کننده اسکن دسته‌ای (Batch Scanner)
// ==========================================
echo "\n--- 4. آزمون هماهنگ‌کننده اسکن دسته‌ای (Batch Scanner) ---\n";
$start_scan = HO_Anti_Batch_Scanner::start_scan();
assert_test(
    'آغاز موفق اسکن دسته‌ای و تولید شناسه یکتا',
    ! empty( $start_scan['scan_id'] ) && $start_scan['total_steps'] > 0
);

$step1 = HO_Anti_Batch_Scanner::process_next_step( $start_scan['scan_id'] );
assert_test(
    'پردازش موفق گام اول اسکن (دیتابیس، ماندگاری و آسیب‌پذیری‌ها)',
    ! empty( $step1['success'] ) && 1 === $step1['current_step']
);

$step2 = HO_Anti_Batch_Scanner::process_next_step( $start_scan['scan_id'] );
assert_test(
    'پردازش موفق گام دوم اسکن (یکپارچگی فایل‌های هسته)',
    ! empty( $step2['success'] ) && 2 === $step2['current_step']
);


// ==========================================
// بخش پنجم: تست حملات جدید (EtherHiding، دستکاری Site URL و فایل‌های غیررسمی)
// ==========================================
echo "\n--- 5. آزمون‌های مهار حملات پیشرفته (EtherHiding, Core Integrity, Site URL Guard) ---\n";

// ۵.۱: تست شناسایی بدافزار اسمارت کانترکت پالیگان و EtherHiding
$etherhiding_code = '<script data-no-optimize="1">(function(){var R=["https://1rpc.io/matic","https://polygon-bor-rpc.publicnode.com"];var a="0xb29927B7D854b232D5E58CFc201866376E68C676";var body=JSON.stringify({jsonrpc:"2.0",id:1,method:"eth_call",params:[{to:a,data:"0x2cae8ae4"},"latest"]});})()</script>';
$test_eh_file = $sandbox_dir . '/test-etherhiding.php';
file_put_contents( $test_eh_file, "<?php // Header\n" . $etherhiding_code );

$malware_engine = new HO_Anti_Malware_Engine();
$eh_findings = $malware_engine->scan( [ $test_eh_file ] );
$found_eh_rule = false;
foreach ( $eh_findings as $f ) {
    if ( 'MAL_ETHERHIDING_WEB3_RPC' === $f->get_rule_id() ) {
        $found_eh_rule = true;
        break;
    }
}
assert_test(
    'تشخیص قطعی بدافزار بلاکچین و Web3 C2 پالیگان (EtherHiding Campaign)',
    $found_eh_rule
);

// ۵.۲: تست پالایشگر بلادرنگ خروجی (Real-time Frontend Output Buffer Sanitizer)
$protection = HO_Anti_Protection::get_instance();
$raw_html = '<html><head>' . $etherhiding_code . '<title>Site</title></head><body>Hello</body></html>';
$sanitized_html = $protection->sanitize_frontend_output( $raw_html );
assert_test(
    'پالایشگر خروجی زنده: خنثی‌سازی و حذف بلادرنگ تگ اسکریپت EtherHiding از HTML',
    false === strpos( $sanitized_html, 'polygon-bor-rpc' ) && false !== strpos( $sanitized_html, 'EtherHiding/Web3 C2 Injection Neutralized' )
);

// ۵.۳: تست حذف ایمن فایل غیررسمی هسته با ثبت در قرنطینه
$rogue_core_file = $sandbox_dir . '/class-wp-plugins-list-table.php';
file_put_contents( $rogue_core_file, "<?php // Rogue backdoor file in wp-admin\n" . $etherhiding_code );

$safe_delete_res = HO_Anti_Cleaner::delete_file_safely( $rogue_core_file, 'حذف فایل غیررسمی هسته در تست' );
assert_test(
    'حذف امن فایل غیررسمی با پشتیبان‌گیری در قرنطینه قبل از حذف',
    ! empty( $safe_delete_res['success'] ) && ! file_exists( $rogue_core_file ) && ! empty( $safe_delete_res['backup_id'] )
);

// ۵.۴: تست نگهبان آدرس سایت در برابر دستکاری دیتابیس (Site URL Option Guard)
$hacked_siteurl = 'https://malicious-spam-redirect.ru/gate';
$blocked_val = $protection->guard_siteurl_option( $hacked_siteurl, 'https://example.com' );
assert_test(
    'نگهبان دیتابیس: مسدودسازی خودکار تلاش برای تغییر آدرس سایت به دامنه اسپم خارجی (.ru)',
    $blocked_val === 'https://example.com'
);

// ۵.۵: تست فیلتر بلادرنگ آدرس سایت در صورت وجود دامنه مخرب در دیتابیس
$filtered_url = $protection->filter_tampered_siteurl( 'https://some-hacked-domain.top/evil' );
assert_test(
    'فیلتر بلادرنگ: بازگردانی آدرس سالم هنگام تلاش برای ریدایرکت بازدیدکنندگان به دامنه اسپم',
    false === strpos( $filtered_url, '.top/evil' )
);

// ۵.۶: تست پایش و اصلاح خودکار سطوح دسترسی ناامن (File Permissions Watchdog)
$perm_test_file = $sandbox_dir . '/wp-login.php';
if ( file_exists( $perm_test_file ) ) {
    @chmod( $perm_test_file, 0666 );
}
file_put_contents( $perm_test_file, '<?php // Login' );
@chmod( $perm_test_file, 0777 );
$reverted = HO_Anti_Protection::enforce_strict_permissions();
$cur_perms = substr( sprintf( '%o', fileperms( $perm_test_file ) ), -4 );
assert_test(
    'نگهبان سطوح دسترسی: شناسایی و اصلاح خودکار فایل دارای دسترسی ناامن به 0444 یا 0644',
    '0777' !== $cur_perms
);
@chmod( $perm_test_file, 0666 );

// ۵.۷: تست ثبت و بازیابی لاگ‌های امنیتی ساختاریافته
HO_Anti_Protection::record_security_event( 'test_event', 'پیام آزمایشی ثبت رویداد امنیتی', [ 'detail' => 'test' ] );
$sec_logs = HO_Anti_Protection::get_security_logs();
$found_log = false;
foreach ( $sec_logs as $lg ) {
    if ( isset( $lg['type'] ) && 'test_event' === $lg['type'] ) {
        $found_log = true;
        break;
    }
}
assert_test(
    'سیستم لاگ ساختاریافته: ثبت موفق و قابل بازیابی تاریخچه رویدادهای امنیتی با متادیتا',
    $found_log
);


// ==========================================
// نتایج نهایی تست
// ==========================================
echo "\n========================================================\n";
echo "خلاصه نتایج آزمون‌های پذیرش:\n";
echo "تعداد کل تست‌های اجرا شده: $tests_run\n";
echo "تست‌های موفق (Passed): $tests_passed\n";
echo "تست‌های ناموفق (Failed): $tests_failed\n";
$success_rate = round( ( $tests_passed / $tests_run ) * 100, 1 );
echo "نرخ موفقیت: $success_rate%\n";
echo "========================================================\n";

if ( 0 === $tests_failed ) {
    echo "STATUS: ALL ACCEPTANCE TESTS PASSED (PRODUCTION READY)\n";
    exit( 0 );
} else {
    echo "STATUS: SOME TESTS FAILED\n";
    exit( 1 );
}
