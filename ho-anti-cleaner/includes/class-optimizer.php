<?php
/**
 * Optimizer and Security Hardening Engine for HO Anti Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Optimizer' ) ) {

    class HO_Anti_Optimizer {

        public static function optimize_database() {
            global $wpdb;

            $report = [
                'tables_optimized'   => 0,
                'transients_cleaned' => 0,
                'revisions_cleaned'  => 0,
                'spam_cleaned'       => 0,
                'log'                => [],
            ];

            // ۱. بهینه‌سازی جداول
            $tables = $wpdb->get_col( "SHOW TABLES LIKE '{$wpdb->prefix}%'" );
            if ( ! empty( $tables ) ) {
                foreach ( $tables as $tbl ) {
                    $wpdb->query( "OPTIMIZE TABLE `$tbl`" );
                    $report['tables_optimized']++;
                }
            }
            $report['log'][] = "تعداد {$report['tables_optimized']} جدول دیتابیس دیفرگ و بهینه‌سازی شدند.";

            // ۲. رونوشت‌های کهنه
            $revisions_deleted = $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_type = 'revision'" );
            $report['revisions_cleaned'] = (int) $revisions_deleted;
            if ( $revisions_deleted > 0 ) {
                $report['log'][] = "تعداد $revisions_deleted رونوشت قدیمی پست‌ها پاک‌سازی شدند.";
            }

            // ۳. پیش‌نویس‌های خودکار
            $wpdb->query( "DELETE FROM {$wpdb->posts} WHERE post_status = 'auto-draft' AND post_modified < DATE_SUB(NOW(), INTERVAL 7 DAY)" );

            // ۴. ترنزینت‌های منقضی
            $transients = $wpdb->query( "DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b
                WHERE a.option_name LIKE '_transient_%'
                AND a.option_name NOT LIKE '_transient_timeout_%'
                AND b.option_name = CONCAT('_transient_timeout_', SUBSTRING(a.option_name, 12))
                AND b.option_value < UNIX_TIMESTAMP()" );
            $report['transients_cleaned'] = (int) $transients;
            if ( $transients > 0 ) {
                $report['log'][] = "تعداد $transients ترنزینت منقضی‌شده از حافظه موقت دیتابیس پاک شدند.";
            }

            // ۵. اسپم‌ها
            $spam_deleted = $wpdb->query( "DELETE FROM {$wpdb->comments} WHERE comment_approved IN ('spam', 'trash')" );
            $report['spam_cleaned'] = (int) $spam_deleted;
            if ( $spam_deleted > 0 ) {
                $report['log'][] = "تعداد $spam_deleted دیدگاه اسپم و زباله‌دان پاک شدند.";
            }

            // ۶. متادیتاهای یتیم
            $wpdb->query( "DELETE pm FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} wp ON wp.ID = pm.post_id WHERE wp.ID IS NULL" );

            return [
                'success' => true,
                'report'  => $report,
            ];
        }

        public static function audit_security_health() {
            $checks = [];

            // ۱. بررسی فایل wp-config.php
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
                $config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( file_exists( $config_path ) ) {
                $perms = substr( sprintf( '%o', fileperms( $config_path ) ), -4 );
                $is_safe = in_array( $perms, [ '0600', '0640', '0644', '0400', '0440', '0444' ], true );
                $checks[] = [
                    'key'      => 'wp_config_perms',
                    'title'    => 'سطح دسترسی فایل wp-config.php',
                    'status'   => $is_safe ? 'good' : 'warning',
                    'detail'   => "سطح دسترسی فعلی: $perms" . ( $is_safe ? ' (مناسب)' : ' (پیشنهاد می‌شود 0640 یا 0600 تنظیم شود)' ),
                    'fixable'  => ! $is_safe,
                ];
            }

            // ۲. وضعیت خطایابی
            $debug_display = defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;
            $checks[] = [
                'key'      => 'debug_display',
                'title'    => 'نمایش خطاهای PHP در سایت (WP_DEBUG_DISPLAY)',
                'status'   => $debug_display ? 'danger' : 'good',
                'detail'   => $debug_display ? 'خطاهای سیستمی برای عموم کاربران نمایش داده می‌شوند! (حتماً غیرفعال کنید)' : 'غیرفعال و امن است.',
                'fixable'  => (bool) $debug_display,
            ];

            // ۳. بررسی پوشه wp-content
            $content_dir = WP_CONTENT_DIR;
            if ( file_exists( $content_dir ) ) {
                $content_perms = substr( sprintf( '%o', fileperms( $content_dir ) ), -4 );
                $is_safe = in_array( $content_perms, [ '0755', '0750' ], true );
                $checks[] = [
                    'key'      => 'wp_content_perms',
                    'title'    => 'سطح دسترسی پوشه wp-content',
                    'status'   => $is_safe ? 'good' : ( '0777' === $content_perms ? 'danger' : 'warning' ),
                    'detail'   => "مجوز فعلی: $content_perms (استاندارد: 0755)",
                    'fixable'  => ! $is_safe,
                ];
            }

            // ۴. نسخه PHP
            $memory = ini_get( 'memory_limit' );
            $checks[] = [
                'key'      => 'php_version',
                'title'    => 'نسخه PHP و محدودیت حافظه',
                'status'   => version_compare( PHP_VERSION, '7.4', '>=' ) ? 'good' : 'warning',
                'detail'   => 'نسخه PHP: ' . PHP_VERSION . ' | حافظه مجاز: ' . $memory,
                'fixable'  => false,
            ];

            return $checks;
        }

        /**
         * اصلاح و غیرفعال‌سازی نمایش خطاهای PHP در سایت (WP_DEBUG_DISPLAY)
         */
        public static function fix_debug_display() {
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
                $config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( ! file_exists( $config_path ) || ! is_readable( $config_path ) ) {
                return [ 'success' => false, 'message' => 'فایل wp-config.php یافت نشد یا قابل خواندن نیست.' ];
            }

            $content = @file_get_contents( $config_path );
            if ( empty( $content ) ) {
                return [ 'success' => false, 'message' => 'محتوای فایل wp-config.php خالی است.' ];
            }

            $was_locked = ! is_writable( $config_path );
            if ( $was_locked ) {
                @chmod( $config_path, 0644 );
            }

            // ۱. اگر WP_DEBUG_DISPLAY از قبل به صورت true تعریف شده، آن را به false تغییر می‌دهیم
            $pattern_display = "/define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*(?:true|1)\s*\);/i";
            if ( preg_match( $pattern_display, $content ) ) {
                $content = preg_replace( $pattern_display, "define( 'WP_DEBUG_DISPLAY', false );", $content );
            } elseif ( false === strpos( $content, 'WP_DEBUG_DISPLAY' ) ) {
                // اگر وجود ندارد، همراه با @ini_set اضافه می‌کنیم
                $insert = "define( 'WP_DEBUG_DISPLAY', false );\n@ini_set( 'display_errors', '0' );\n";
                $search = "/* That's all, stop editing! Happy publishing. */";
                if ( false !== strpos( $content, $search ) ) {
                    $content = str_replace( $search, $insert . $search, $content );
                } else {
                    $content = preg_replace( '/<\?php\s*/', "<?php\n" . $insert, $content, 1 );
                }
            }

            if ( false === @file_put_contents( $config_path, $content ) ) {
                if ( $was_locked ) @chmod( $config_path, 0444 );
                return [ 'success' => false, 'message' => 'خطا در ذخیره تغییرات در wp-config.php. دسترسی فایل را بررسی کنید.' ];
            }

            if ( $was_locked || get_option( 'ho_anti_files_locked', 1 ) ) {
                @chmod( $config_path, 0444 );
            }

            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'debug_display_fixed',
                    'نمایش خطاهای عمومی PHP در سایت (WP_DEBUG_DISPLAY) با موفقیت غیرفعال و ایمن‌سازی شد.'
                );
            }

            return [
                'success' => true,
                'message' => 'نمایش خطاهای PHP در سایت با موفقیت غیرفعال شد (WP_DEBUG_DISPLAY = false). خطاهای سیستمی دیگر به عموم نمایش داده نخواهند شد.',
            ];
        }

        /**
         * اصلاح و استانداردسازی سطح دسترسی پوشه wp-content و زیرپوشه‌ها به 0755
         */
        public static function fix_wp_content_permissions() {
            $content_dir = WP_CONTENT_DIR;
            if ( ! file_exists( $content_dir ) ) {
                return [ 'success' => false, 'message' => 'پوشه wp-content یافت نشد.' ];
            }

            @chmod( $content_dir, 0755 );
            $fixed_subdirs = 0;

            // اصلاح زیرپوشه‌های اصلی مانند plugins, themes, uploads
            $subdirs = [
                defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : $content_dir . '/plugins',
                function_exists( 'get_theme_root' ) ? get_theme_root() : $content_dir . '/themes',
                $content_dir . '/uploads',
                $content_dir . '/languages',
            ];

            foreach ( $subdirs as $dir ) {
                if ( is_dir( $dir ) ) {
                    $p = substr( sprintf( '%o', fileperms( $dir ) ), -4 );
                    if ( in_array( $p, [ '0777', '0775', '0666' ], true ) ) {
                        if ( @chmod( $dir, 0755 ) ) {
                            $fixed_subdirs++;
                        }
                    }
                }
            }

            $current_perms = substr( sprintf( '%o', fileperms( $content_dir ) ), -4 );

            if ( in_array( $current_perms, [ '0755', '0750' ], true ) ) {
                if ( class_exists( 'HO_Anti_Protection' ) ) {
                    HO_Anti_Protection::record_security_event(
                        'permissions_fixed',
                        "سطح دسترسی پوشه wp-content به {$current_perms} استانداردسازی شد.",
                        [ 'perms' => $current_perms, 'subdirs_fixed' => $fixed_subdirs ]
                    );
                }

                return [
                    'success' => true,
                    'perms'   => $current_perms,
                    'message' => "سطح دسترسی پوشه wp-content با موفقیت به {$current_perms} (استاندارد امن وردپرس) تغییر یافت و مجوز ناامن 0777 خنثی شد.",
                ];
            }

            return [
                'success' => false,
                'message' => "خطا در تغییر سطح دسترسی. ممکن است مالکیت وب‌سرور (Owner/Group) محدود شده باشد (مجوز فعلی: {$current_perms}).",
            ];
        }

        /**
         * اصلاح سطح دسترسی فایل wp-config.php به حالت امن
         */
        public static function fix_wp_config_permissions() {
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
                $config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( ! file_exists( $config_path ) ) {
                return [ 'success' => false, 'message' => 'فایل wp-config.php یافت نشد.' ];
            }

            $target_perm = get_option( 'ho_anti_files_locked', 1 ) ? 0444 : 0640;
            @chmod( $config_path, $target_perm );
            $new_perm = substr( sprintf( '%o', fileperms( $config_path ) ), -4 );

            return [
                'success' => true,
                'perms'   => $new_perm,
                'message' => "سطح دسترسی فایل wp-config.php با موفقیت به {$new_perm} تنظیم شد.",
            ];
        }

        /**
         * دیسپچر متمرکز اصلاح بررسی‌های امنیتی
         */
        public static function fix_security_check( $check_key ) {
            switch ( $check_key ) {
                case 'debug_display':
                    return self::fix_debug_display();
                case 'wp_content_perms':
                    return self::fix_wp_content_permissions();
                case 'wp_config_perms':
                    return self::fix_wp_config_permissions();
                default:
                    return [ 'success' => false, 'message' => 'نوع بررسی امنیتی نامعتبر است: ' . esc_html( $check_key ) ];
            }
        }

        public static function generate_fresh_salts() {
            $keys = [
                'AUTH_KEY',
                'SECURE_AUTH_KEY',
                'LOGGED_IN_KEY',
                'NONCE_KEY',
                'AUTH_SALT',
                'SECURE_AUTH_SALT',
                'LOGGED_IN_SALT',
                'NONCE_SALT',
            ];

            $output = '';
            foreach ( $keys as $key ) {
                $random_str = wp_generate_password( 64, true, true );
                $output .= "define( '{$key}', " . var_export( $random_str, true ) . " );\n";
            }

            return $output;
        }
    }

    if ( ! class_exists( 'AFC_Optimizer' ) ) {
        class_alias( 'HO_Anti_Optimizer', 'AFC_Optimizer' );
    }
}
