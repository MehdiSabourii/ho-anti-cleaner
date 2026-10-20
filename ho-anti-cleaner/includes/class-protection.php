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
         * سخت‌سازی فایل wp-config.php با نوشتن DISALLOW_FILE_EDIT
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
            if ( false !== strpos( $content, 'DISALLOW_FILE_EDIT' ) ) {
                return [ 'success' => true, 'message' => 'دستور DISALLOW_FILE_EDIT از قبل در wp-config.php وجود دارد.' ];
            }

            $addition = "\n/* HO Anti Hardening: Disable In-Dashboard File Editing */\ndefine( 'DISALLOW_FILE_EDIT', true );\n";
            $search = "/* That's all, stop editing! Happy publishing. */";

            if ( false !== strpos( $content, $search ) ) {
                $content = str_replace( $search, $addition . "\n" . $search, $content );
            } else {
                $content = preg_replace( '/<\?php\s*/', "<?php\n" . $addition, $content, 1 );
            }

            if ( false !== @file_put_contents( $config_path, $content ) ) {
                return [ 'success' => true, 'message' => 'قابلیت ویرایش فایل‌ها از پیشخوان با موفقیت در wp-config.php غیرفعال شد.' ];
            }

            return [ 'success' => false, 'message' => 'خطا در بازنویسی wp-config.php.' ];
        }

        /**
         * ثبت وقایع امنیتی
         */
        public static function record_security_event( $type, $message, $meta = [] ) {
            $logs = get_option( 'ho_anti_security_logs', [] );
            if ( ! is_array( $logs ) ) {
                $logs = [];
            }

            $entry = [
                'time'    => current_time( 'mysql' ),
                'type'    => $type,
                'message' => $message,
                'meta'    => $meta,
            ];

            array_unshift( $logs, $entry );
            if ( count( $logs ) > 60 ) {
                $logs = array_slice( $logs, 0, 60 );
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

        public function scheduled_watchdog_run() {
            $this->maybe_run_self_healing();
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
