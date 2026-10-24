<?php
/**
 * Active Protection & Anti-Injection Engine for HO Anti Cleaner
 * موتور محافظت بلادرنگ، قفل فایل‌های حساس و ضد تزریق کد به وردپرس
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Protection' ) ) {

    class HO_Anti_Protection {

        private static $instance = null;

        public static function get_instance() {
            if ( null === self::$instance ) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        private function __construct() {
            // ۱. فایروال پیشگیرانه در اولین مرحله لودینگ وردپرس
            $this->init_firewall();

            // ۲. خودترمیم‌کننده و نگهبان فایل‌های هسته
            add_action( 'init', [ $this, 'maybe_run_self_healing' ], 1 );

            // ۳. سخت‌سازی خودکار در سطح زمان اجرا
            $this->enforce_runtime_security();

            // ۴. رویداد زمان‌بندی‌شده دوره‌ای جهت نگهبانی و بررسی قفل‌ها
            add_action( 'ho_anti_hourly_watchdog', [ $this, 'scheduled_watchdog_run' ] );
            if ( ! wp_next_scheduled( 'ho_anti_hourly_watchdog' ) ) {
                wp_schedule_event( time(), 'hourly', 'ho_anti_hourly_watchdog' );
            }

            // ۵. فایروال خروجی زنده (Real-time Frontend Output Sanitizer) جهت پاک‌سازی بلادرنگ EtherHiding و ریدایرکت‌های مخرب
            if ( ! is_admin() && get_option( 'ho_anti_output_sanitizer_enabled', 1 ) ) {
                add_action( 'template_redirect', [ $this, 'start_output_sanitization' ], -99999 );
            }

            // ۶. محافظت از دستکاری آدرس اصلی سایت در دیتابیس (Site URL & Home Option Guard)
            add_filter( 'pre_update_option_siteurl', [ $this, 'guard_siteurl_option' ], 10, 2 );
            add_filter( 'pre_update_option_home',    [ $this, 'guard_siteurl_option' ], 10, 2 );
            add_filter( 'option_siteurl',            [ $this, 'filter_tampered_siteurl' ] );
            add_filter( 'option_home',               [ $this, 'filter_tampered_siteurl' ] );
        }

        /**
         * لیست فایل‌های بحرانی و حساس وردپرس که هدف اصلی تزریق کد هستند
         */
        public static function get_critical_files() {
            $root = ABSPATH;
            $config_path = $root . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( $root ) . '/wp-config.php' ) ) {
                $config_path = dirname( $root ) . '/wp-config.php';
            }

            return [
                'wp-login.php'    => $root . 'wp-login.php',
                'index.php'       => $root . 'index.php',
                'wp-config.php'   => $config_path,
                'wp-settings.php' => $root . 'wp-settings.php',
                'wp-load.php'     => $root . 'wp-load.php',
                'xmlrpc.php'      => $root . 'xmlrpc.php',
                'wp-cron.php'     => $root . 'wp-cron.php',
                'wp-blog-header'  => $root . 'wp-blog-header.php',
                '.htaccess'       => $root . '.htaccess',
                '.user.ini'       => $root . '.user.ini',
            ];
        }

        /**
         * ۱. فایروال پیشگیرانه (Micro-Firewall)
         */
        private function init_firewall() {
            if ( ! get_option( 'ho_anti_firewall_enabled', 1 ) ) {
                return;
            }

            // الف) بررسی کوکی‌های درپشتی شناخته‌شده (مانند yrxc_uck)
            if ( ! empty( $_COOKIE ) ) {
                foreach ( $_COOKIE as $k => $v ) {
                    if ( false !== strpos( $k, 'yrxc_u' ) || false !== strpos( $k, 'yrxc_uck' ) ) {
                        self::record_security_event( 'firewall_blocked_cookie', "مسدودسازی مهاجم با کوکی درب‌پشتی ($k)", [
                            'ip'         => self::get_client_ip(),
                            'cookie'     => $k,
                            'uri'        => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : '',
                            'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '',
                        ] );
                        wp_die(
                            '<div dir="rtl" style="font-family:tahoma; padding:20px; color:#b91c1c;"><h2>دسترسی غیرمجاز (مسدودشده توسط فایروال HO Anti)</h2><p>شناسه کوکی ارسالی در لیست سیاه تهدیدات امنیتی قرار دارد.</p></div>',
                            'Access Denied - 403',
                            [ 'response' => 403 ]
                        );
                    }
                }
            }

            // ب) بررسی پارامترهای درخواست برای کشف رفتارهای وب‌شل و تزریق RCE
            $suspicious_inputs = array_merge( $_GET, $_POST );
            if ( ! empty( $suspicious_inputs ) ) {
                foreach ( $suspicious_inputs as $key => $val ) {
                    if ( ! is_string( $val ) ) continue;

                    // بررسی اجرای دستورات شل یا دکد مستقیم base64/eval
                    if ( preg_match( '/(?:passthru|shell_exec|base64_decode\s*\(|gzinflate\s*\(|file_put_contents\s*\()/i', $val ) ) {
                        // استثنا برای پیشخوان مدیر
                        if ( current_user_can( 'manage_options' ) && is_admin() ) {
                            continue;
                        }

                        self::record_security_event( 'firewall_blocked_payload', "مسدودسازی پی‌لود مخرب RCE/Eval در پارامتر ($key)", [
                            'ip'  => self::get_client_ip(),
                            'uri' => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : '',
                        ] );

                        wp_die(
                            '<div dir="rtl" style="font-family:tahoma; padding:20px; color:#b91c1c;"><h2>درخواست مشکوک شناسایی و مسدود گردید</h2><p>تلاش برای ارسال کدهای اجرایی توسط فایروال افزونه مهار شد.</p></div>',
                            'Forbidden - 403',
                            [ 'response' => 403 ]
                        );
                    }
                }
            }
        }

        /**
         * ۲. خودترمیم‌کننده و نگهبان فایل‌های هسته (Self-Healing File Guard)
         * در هر بار باز شدن سایت یا ورود، فایل‌های اصلی وردپرس را بررسی و در صورت مشاهده تزریق کد، فوراً جراحی و پاک می‌کند.
         */
        public function maybe_run_self_healing() {
            if ( ! get_option( 'ho_anti_self_healing_enabled', 1 ) ) {
                return;
            }

            // محدود کردن دفعات بررسی برای جلوگیری از مصرف بیهوده I/O (حداکثر یک‌بار در هر ۶۰ ثانیه به جز در صفحه لاگین)
            $is_login_page = ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) ||
                             ( isset( $_SERVER['SCRIPT_NAME'] ) && false !== strpos( $_SERVER['SCRIPT_NAME'], 'wp-login.php' ) );

            if ( ! $is_login_page && false !== get_transient( 'ho_anti_last_self_heal_check' ) ) {
                return;
            }

            set_transient( 'ho_anti_last_self_heal_check', time(), 60 );

            $critical = self::get_critical_files();
            $healed_any = false;

            foreach ( $critical as $name => $path ) {
                if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
                    continue;
                }

                $content = @file_get_contents( $path, false, null, 0, 4096 );
                if ( empty( $content ) ) {
                    continue;
                }

                // بررسی وجود امضای کدهای مخرب در بالای فایل (Header Gatekeeper)
                if ( self::has_header_malware( $content ) ) {
                    $full_content = @file_get_contents( $path );
                    $cleaned = self::strip_header_malware( $full_content );

                    if ( false !== $cleaned && $cleaned !== $full_content ) {
                        // ذخیره نسخه قرنطینه قبل از بازنویسی
                        HO_Anti_Cleaner::backup_file_external( $path );

                        // در صورتی که فایل فقط خواندنی (0444) باشد، موقتاً مجوز را به 0644 تغییر می‌دهیم
                        $is_writable = is_writable( $path );
                        if ( ! $is_writable ) {
                            @chmod( $path, 0644 );
                        }

                        if ( false !== @file_put_contents( $path, $cleaned ) ) {
                            $healed_any = true;
                            // قفل مجدد فایل به 0444 جهت جلوگیری از تزریق مجدد
                            if ( get_option( 'ho_anti_files_locked', 1 ) ) {
                                @chmod( $path, 0444 );
                            }

                            self::record_security_event( 'self_healed', "ترمیم خودکار و بلادرنگ فایل ($name)؛ کد مخرب تزریقی هکر حذف و فایل سالم شد.", [
                                'file' => $name,
                                'time' => current_time( 'mysql' ),
                            ] );
                        }
                    }
                }
            }

            // اگر گزینه‌ی قفل فعال است، بررسی می‌کنیم که فایل‌ها از 0444 خارج نشده باشند
            if ( get_option( 'ho_anti_files_locked', 1 ) && $is_login_page ) {
                self::lock_critical_files();
            }
        }

        /**
         * بررسی وجود کد مسدودکننده و گیت‌کیپر در ابتدای فایل
         */
        public static function has_header_malware( $content ) {
            if ( empty( $content ) ) {
                return false;
            }

            if ( false !== strpos( $content, 'yrxc_u' ) ) {
                return true;
            }

            if ( preg_match( '/while\s*\(\s*md5\s*\(\s*md5\s*\(/i', $content ) ) {
                return true;
            }

            if ( false !== strpos( $content, 'fe98788c6cf41c9f48e53cc93245c23c' ) || false !== strpos( $content, '98788c' ) ) {
                return true;
            }

            if ( preg_match( '/<\?php\s*(?:while|if)\s*\([^;]+die\s*\(\s*\)\s*;?/is', $content ) ) {
                return true;
            }

            return false;
        }

        /**
         * جراحی و حذف کد مخرب از ابتدای فایل
         */
        public static function strip_header_malware( $content ) {
            if ( empty( $content ) ) {
                return false;
            }

            // الگوی دقیق تزریق گیت‌کیپر کوکی
            $patterns = [
                // while(md5(md5(isset($_COOKIE...)))) { die(); }
                '/<\?php\s*while\s*\(\s*md5\s*\(\s*md5\s*\(.+?die\s*\(\s*\)\s*;?\s*\}?/is',
                // while(md5(md5(isset($_COOKIE["yrxc_u"."ck"])...
                '/<\?php\s*while\s*\([^;]*yrxc_u[^;]*;?\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
                // هدرهای مخرب شامل die بلافاصله پس از <?php
                '/<\?php\s*(?:while|if)\s*\([^)]*md5[^)]*\)\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
            ];

            foreach ( $patterns as $pat ) {
                if ( preg_match( $pat, $content ) ) {
                    $cleaned = preg_replace( $pat, "<?php\n", $content, 1 );
                    if ( ! empty( $cleaned ) ) {
                        return $cleaned;
                    }
                }
            }

            return false;
        }

        /**
         * ۳. قفل کردن فایل‌های حساس به حالت فقط خواندنی (Chmod 0444)
         * در لینوکس، وقتی فایل 0444 باشد، پروسه‌های PHP معمولی دسترسی نوشتن و ویرایش آن را نخواهند داشت.
         */
        public static function lock_critical_files() {
            $files = self::get_critical_files();
            $results = [];

            foreach ( $files as $name => $path ) {
                if ( file_exists( $path ) ) {
                    $current_perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
                    if ( '0444' !== $current_perms ) {
                        @chmod( $path, 0444 );
                    }
                    $new_perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
                    $results[ $name ] = [
                        'path'     => $path,
                        'perms'    => $new_perms,
                        'locked'   => ( '0444' === $new_perms || ! is_writable( $path ) ),
                        'writable' => is_writable( $path ),
                    ];
                }
            }

            update_option( 'ho_anti_files_locked', 1 );
            return $results;
        }

        /**
         * باز کردن قفل فایل‌های حساس جهت انجام به‌روزرسانی‌های قانونی (Chmod 0644)
         */
        public static function unlock_critical_files() {
            $files = self::get_critical_files();
            $results = [];

            foreach ( $files as $name => $path ) {
                if ( file_exists( $path ) ) {
                    @chmod( $path, 0644 );
                    $new_perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
                    $results[ $name ] = [
                        'path'     => $path,
                        'perms'    => $new_perms,
                        'locked'   => false,
                        'writable' => is_writable( $path ),
                    ];
                }
            }

            update_option( 'ho_anti_files_locked', 0 );
            return $results;
        }

        /**
         * دریافت وضعیت قفل فایل‌های حساس
         */
        public static function get_lock_status() {
            $files = self::get_critical_files();
            $status = [];

            foreach ( $files as $name => $path ) {
                $exists = file_exists( $path );
                $perms = $exists ? substr( sprintf( '%o', fileperms( $path ) ), -4 ) : '-';
                $writable = $exists ? is_writable( $path ) : false;

                $status[] = [
                    'name'     => $name,
                    'path'     => $path,
                    'exists'   => $exists,
                    'perms'    => $perms,
                    'locked'   => ( '0444' === $perms || ( $exists && ! $writable ) ),
                    'writable' => $writable,
                ];
            }

            return $status;
        }

        /**
         * ۴. نصب سپر ضد اجرای PHP در پوشه آپلودها و wp-includes
         */
        public static function install_execution_shields() {
            $log = [];

            // الف) محافظت از uploads
            $upload_dir = wp_upload_dir();
            $uploads_basedir = $upload_dir['basedir'];
            if ( is_dir( $uploads_basedir ) ) {
                $ht_path = $uploads_basedir . '/.htaccess';
                $rules = "# HO Anti Security Shield - Block PHP Execution\n"
                       . "<FilesMatch \"(?i)\\.(php|php[0-9]?|phtml|phar|pl|py|cgi|asp|aspx|sh|exe)$\">\n"
                       . "    Order Deny,Allow\n"
                       . "    Deny from all\n"
                       . "</FilesMatch>\n"
                       . "Options -Indexes -ExecCGI\n";

                if ( false !== @file_put_contents( $ht_path, $rules ) ) {
                    @chmod( $ht_path, 0444 );
                    $log[] = 'سپر حفاظتی htaccess در پوشه uploads مستقر شد (اجرای هرگونه فایل PHP مسدود گردید).';
                }
            }

            // ب) محافظت از wp-includes
            $includes_dir = ABSPATH . WPINC;
            if ( is_dir( $includes_dir ) ) {
                $ht_inc = $includes_dir . '/.htaccess';
                if ( ! file_exists( $ht_inc ) ) {
                    $rules_inc = "# HO Anti Security Shield - wp-includes protection\n"
                               . "<Files wp-tinymce.php>\n"
                               . "    Allow from all\n"
                               . "</Files>\n"
                               . "<Files ms-files.php>\n"
                               . "    Allow from all\n"
                               . "</Files>\n"
                               . "<FilesMatch \"(?i)\\.(php|phtml)$\">\n"
                               . "    Order Deny,Allow\n"
                               . "    Deny from all\n"
                               . "</FilesMatch>\n";
                    if ( false !== @file_put_contents( $ht_inc, $rules_inc ) ) {
                        @chmod( $ht_inc, 0444 );
                        $log[] = 'سپر حفاظتی htaccess در پوشه wp-includes با موفقیت مستقر شد.';
                    }
                }
            }

            return [ 'success' => true, 'log' => $log ];
        }

        /**
         * ۵. اسکن و پاک‌سازی رویدادهای مخرب در WP-Cron
         */
        public static function audit_cron_jobs() {
            $crons = _get_cron_array();
            $report = [
                'total'      => 0,
                'suspicious' => [],
            ];

            if ( empty( $crons ) || ! is_array( $crons ) ) {
                return $report;
            }

            $suspicious_names = [ 'av_', 'sys_', 'opt_', 'check_version_update', 'wp_sys', 'assetflow' ];

            foreach ( $crons as $timestamp => $hooks ) {
                foreach ( $hooks as $hook => $data ) {
                    $report['total']++;
                    $is_suspicious = false;
                    $reason = '';

                    foreach ( $suspicious_names as $needle ) {
                        if ( false !== stripos( $hook, $needle ) ) {
                            $is_suspicious = true;
                            $reason = "نام مشکوک به بدافزار ($needle)";
                            break;
                        }
                    }

                    // بررسی وجود توابع ثبت شده
                    if ( ! has_action( $hook ) && $is_suspicious ) {
                        $reason .= ' | قلاب بدون اکشن معتبر در سیستم';
                    }

                    if ( $is_suspicious ) {
                        $report['suspicious'][] = [
                            'hook'      => $hook,
                            'timestamp' => $timestamp,
                            'date'      => date( 'Y-m-d H:i:s', $timestamp ),
                            'reason'    => $reason,
                        ];
                    }
                }
            }

            return $report;
        }

        public static function clean_suspicious_crons() {
            $crons = _get_cron_array();
            $cleaned = 0;
            $suspicious_names = [ 'av_', 'sys_', 'opt_', 'check_version_update', 'wp_sys', 'assetflow' ];

            if ( ! empty( $crons ) && is_array( $crons ) ) {
                foreach ( $crons as $timestamp => $hooks ) {
                    foreach ( $hooks as $hook => $data ) {
                        foreach ( $suspicious_names as $needle ) {
                            if ( false !== stripos( $hook, $needle ) ) {
                                wp_clear_scheduled_hook( $hook );
                                $cleaned++;
                                break;
                            }
                        }
                    }
                }
            }

            return [
                'success' => true,
                'cleaned' => $cleaned,
                'message' => $cleaned > 0 ? "تعداد $cleaned کران‌جاب مشکوک حذف شدند." : "کران‌جاب مشکوکی یافت نشد.",
            ];
        }

        /**
         * ۶. سخت‌سازی زمان اجرا (DISALLOW_FILE_EDIT)
         */
        private function enforce_runtime_security() {
            if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
                define( 'DISALLOW_FILE_EDIT', true );
            }
        }

        /**
         * سخت‌سازی فایل wp-config.php با نوشتن DISALLOW_FILE_EDIT و قفل آدرس سایت (WP_SITEURL و WP_HOME)
         */
        public static function apply_wp_config_hardening() {
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
                $config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( ! file_exists( $config_path ) || ! is_writable( $config_path ) ) {
                return [ 'success' => false, 'message' => 'فایل wp-config.php یافت نشد یا قابل نوشتن نیست.' ];
            }

            $content = file_get_contents( $config_path );
            $siteurl = esc_url_raw( get_option( 'siteurl' ) );
            $home    = esc_url_raw( get_option( 'home' ) );

            $hardened_parts = [];

            if ( false !== strpos( $content, 'DISALLOW_FILE_EDIT' ) ) {
                // از قبل وجود دارد
            } else {
                $hardened_parts[] = "define( 'DISALLOW_FILE_EDIT', true );";
            }

            if ( false === strpos( $content, 'WP_SITEURL' ) && ! empty( $siteurl ) ) {
                $hardened_parts[] = "if ( ! defined( 'WP_SITEURL' ) ) define( 'WP_SITEURL', '{$siteurl}' );";
            }

            if ( false === strpos( $content, 'WP_HOME' ) && ! empty( $home ) ) {
                $hardened_parts[] = "if ( ! defined( 'WP_HOME' ) ) define( 'WP_HOME', '{$home}' );";
            }

            if ( empty( $hardened_parts ) ) {
                return [ 'success' => true, 'message' => 'سخت‌سازی جامع wp-config.php (قفل آدرس‌های سایت و غیرفعال‌سازی ویرایشگر فایل) از قبل اعمال شده است.' ];
            }

            $addition = "\n/* HO Anti Hardening: Disable In-Dashboard File Editing & Lock Site URLs against DB Tampering */\n"
                      . implode( "\n", $hardened_parts ) . "\n";
            $search = "/* That's all, stop editing! Happy publishing. */";

            if ( false !== strpos( $content, $search ) ) {
                $content = str_replace( $search, $addition . "\n" . $search, $content );
            } else {
                $content = preg_replace( '/<\?php\s*/', "<?php\n" . $addition, $content, 1 );
            }

            if ( false !== @file_put_contents( $config_path, $content ) ) {
                self::record_security_event(
                    'config_hardened',
                    'سخت‌سازی جامع wp-config.php (قفل آدرس سایت و غیرفعال‌سازی ویرایشگر پیشخوان) با موفقیت اعمال گردید.'
                );
                return [ 'success' => true, 'message' => 'سخت‌سازی جامع wp-config.php (قفل آدرس سایت و غیرفعال‌سازی ویرایشگر پیشخوان) با موفقیت اعمال گردید.' ];
            }

            return [ 'success' => false, 'message' => 'خطا در بازنویسی wp-config.php.' ];
        }

        /**
         * ثبت وقایع امنیتی ساختاریافته در دیتابیس
         */
        public static function record_security_event( $type, $message, $meta = [] ) {
            $logs = get_option( 'ho_anti_security_logs', [] );
            if ( ! is_array( $logs ) ) {
                $logs = [];
            }

            $severity_map = [
                'firewall_blocked_cookie'     => 'critical',
                'firewall_blocked_payload'    => 'critical',
                'frontend_shield_neutralized' => 'critical',
                'siteurl_tamper_blocked'      => 'critical',
                'self_healed'                 => 'high',
                'file_deleted'                => 'high',
                'permissions_enforced'        => 'medium',
                'database_cleaned'            => 'medium',
                'siteurl_restored'            => 'high',
                'config_hardened'             => 'info',
                'scan_completed'              => 'info',
            ];

            $entry = [
                'id'       => 'sec_' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 8 ),
                'time'     => current_time( 'mysql' ),
                'type'     => $type,
                'severity' => isset( $severity_map[ $type ] ) ? $severity_map[ $type ] : 'medium',
                'message'  => $message,
                'meta'     => $meta,
            ];

            array_unshift( $logs, $entry );
            if ( count( $logs ) > 100 ) {
                $logs = array_slice( $logs, 0, 100 );
            }

            update_option( 'ho_anti_security_logs', $logs, false );
        }

        public static function get_security_logs() {
            $logs = get_option( 'ho_anti_security_logs', [] );
            return is_array( $logs ) ? $logs : [];
        }

        public static function clear_security_logs() {
            update_option( 'ho_anti_security_logs', [], false );
            return true;
        }

        /**
         * نگهبان ضد دستکاری آدرس اصلی سایت (Site URL & Home Option Guard)
         * از تغییر ناخواسته آدرس سایت توسط افزونه‌های آلوده، حملات REST API یا تزریق‌های دیتابیس جلوگیری می‌کند.
         */
        public function guard_siteurl_option( $new_value, $old_value ) {
            if ( $new_value === $old_value ) {
                return $new_value;
            }

            // بررسی الگوی دامنه‌های اسپم، فیشینگ یا مشکوک
            $tampered_pat = '/(?:\.ru|\.top|\.xyz|\.click|\.pw|\.cc|\.ws|ngrok|\/gate|\/evil|0x[0-9a-f]{40})/i';
            $is_suspicious = (bool) preg_match( $tampered_pat, $new_value );

            $is_authorized = false;
            if ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
                if ( is_admin() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
                    $is_authorized = true;
                }
            }

            if ( ! $is_authorized || $is_suspicious ) {
                self::record_security_event(
                    'siteurl_tamper_blocked',
                    "تلاش غیرمجاز برای تغییر آدرس اصلی سایت از [{$old_value}] به [{$new_value}] مسدود گردید.",
                    [
                        'attempted_url' => $new_value,
                        'current_url'   => $old_value,
                        'ip'            => self::get_client_ip(),
                        'suspicious'    => $is_suspicious,
                    ]
                );
                return $old_value;
            }

            // به‌روزرسانی آدرس موثق در صورت تغییر قانونی توسط مدیر
            update_option( 'ho_anti_trusted_siteurl', $new_value, false );
            update_option( 'ho_anti_trusted_home', $new_value, false );

            return $new_value;
        }

        /**
         * فیلتر بلادرنگ آدرس‌های دستکاری‌شده سایت جهت جلوگیری از ریدایرکت بازدیدکنندگان
         */
        public function filter_tampered_siteurl( $value ) {
            if ( empty( $value ) || ! is_string( $value ) ) {
                return $value;
            }

            $tampered_pat = '/(?:\.ru|\.top|\.xyz|\.click|\.pw|\.cc|\.ws|ngrok|\/gate|\/evil|0x[0-9a-f]{40})/i';
            if ( preg_match( $tampered_pat, $value ) ) {
                $trusted = get_option( 'ho_anti_trusted_siteurl', '' );
                if ( ! empty( $trusted ) && ! preg_match( $tampered_pat, $trusted ) ) {
                    return $trusted;
                }
                $proto = ( isset( $_SERVER['HTTPS'] ) && 'on' === $_SERVER['HTTPS'] ) ? 'https://' : 'http://';
                $host  = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( $_SERVER['HTTP_HOST'] ) : '';
                if ( ! empty( $host ) ) {
                    return $proto . $host;
                }
                if ( function_exists( 'home_url' ) ) {
                    $home = home_url();
                    if ( ! empty( $home ) && ! preg_match( $tampered_pat, $home ) ) {
                        return $home;
                    }
                }
                return 'https://' . ( isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : 'localhost' );
            }

            return $value;
        }

        /**
         * پایش و اعمال خودکار مجوزهای امنیتی فایل‌ها و بازگردانی مجوزهای ناامن (0666 / 0777)
         */
        public static function enforce_strict_permissions() {
            $files = self::get_critical_files();
            $is_locked = (bool) get_option( 'ho_anti_files_locked', 1 );
            $reverted_count = 0;

            foreach ( $files as $name => $path ) {
                if ( ! file_exists( $path ) ) continue;

                $perms = fileperms( $path );
                if ( false === $perms ) continue;

                $octal = substr( sprintf( '%o', $perms ), -4 );

                if ( $is_locked ) {
                    if ( '0444' !== $octal ) {
                        @chmod( $path, 0444 );
                        $reverted_count++;
                    }
                } else {
                    $is_world_writable = ( ( $perms & 0002 ) !== 0 );
                    if ( in_array( $octal, [ '0666', '0777', '0775' ], true ) || $is_world_writable ) {
                        @chmod( $path, 0644 );
                        $reverted_count++;
                    }
                }
            }

            if ( $reverted_count > 0 ) {
                self::record_security_event(
                    'permissions_enforced',
                    "نگهبان مجوزها ($reverted_count) فایل با سطح دسترسی ناامن را شناسایی و به حالت ایمن بازگرداند.",
                    [ 'reverted_count' => $reverted_count ]
                );
            }

            return $reverted_count;
        }

        /**
         * آغاز بافر خروجی جهت پالایش بلادرنگ HTML قبل از ارسال به مرورگر کاربر
         */
        public function start_output_sanitization() {
            if ( is_admin() || ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) || ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) ) {
                return;
            }
            ob_start( [ $this, 'sanitize_frontend_output' ] );
        }

        /**
         * پالایشگر بلادرنگ خروجی: حذف کدهای تزریقی EtherHiding، Web3 C2 و ریدایرکت‌های اسپم
         */
        public function sanitize_frontend_output( $buffer ) {
            if ( empty( $buffer ) || ! is_string( $buffer ) ) {
                return $buffer;
            }

            $malicious_patterns = [
                // ۱. بدافزار پیشرفته EtherHiding و فراخوانی Web3 RPC پالیگان
                '/<script[^>]*>(?:(?!<\/script>).)*(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call)(?:(?!<\/script>).)*<\/script>/is',
                // ۲. اسکریپت‌های پنهان‌ساز با data-no-optimize و بررسی wp-settings و wpadminbar
                '/<script[^>]*data-no-optimize=[\'"]1[\'"][^>]*>(?:(?!<\/script>).)*(?:wp-settings|wpadminbar)(?:(?!<\/script>).)*(?:XMLHttpRequest|createElement\([\'"]script[\'"]\))(?:(?!<\/script>).)*<\/script>/is',
                // ۳. تزریق کدهای مخرب کلیک‌فیکس یا فیک‌کپچا
                '/<script[^>]*>(?:(?!<\/script>).)*(?:Verify you are human|powershell.*-enc|ClickFix)(?:(?!<\/script>).)*<\/script>/is',
                // ۴. اسکریپت‌های ریدایرکت به دامنه‌های اسپم
                '/<script[^>]*src=[\'"]https?:\/\/[^\'"]*(?:\.ru|\.top|\.xyz|\.click|\.pw)[^\'"]*[\'"][^>]*>\s*<\/script>/i',
            ];

            $cleaned = $buffer;
            $neutralized_count = 0;

            foreach ( $malicious_patterns as $pat ) {
                if ( preg_match( $pat, $cleaned ) ) {
                    $cleaned = preg_replace( $pat, "<!-- [HO Anti Security: EtherHiding/Web3 C2 Injection Neutralized] -->\n", $cleaned );
                    $neutralized_count++;
                }
            }

            if ( $neutralized_count > 0 ) {
                self::record_security_event(
                    'frontend_shield_neutralized',
                    "سپر خروجی زنده ($neutralized_count) اسکریپت بدافزار EtherHiding / Web3 C2 را در درخواست کاربر خنثی کرد.",
                    [
                        'ip'  => self::get_client_ip(),
                        'uri' => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : '',
                    ]
                );
            }

            return $cleaned;
        }

        public function scheduled_watchdog_run() {
            $this->maybe_run_self_healing();
            self::enforce_strict_permissions();
        }

        private static function get_client_ip() {
            if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) return sanitize_text_field( $_SERVER['HTTP_CF_CONNECTING_IP'] );
            if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
                $ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
                return sanitize_text_field( trim( $ips[0] ) );
            }
            return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( $_SERVER['REMOTE_ADDR'] ) : 'unknown';
        }
    }
}
