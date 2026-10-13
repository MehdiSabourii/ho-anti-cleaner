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
                    'title'    => 'سطح دسترسی فایل wp-config.php',
                    'status'   => $is_safe ? 'good' : 'warning',
                    'detail'   => "سطح دسترسی فعلی: $perms" . ( $is_safe ? ' (مناسب)' : ' (پیشنهاد می‌شود 0640 یا 0600 تنظیم شود)' ),
                ];
            }

            // ۲. وضعیت خطایابی
            $debug_display = defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;
            $checks[] = [
                'title'    => 'نمایش خطاهای PHP در سایت (WP_DEBUG_DISPLAY)',
                'status'   => $debug_display ? 'danger' : 'good',
                'detail'   => $debug_display ? 'خطاهای سیستمی برای عموم کاربران نمایش داده می‌شوند! (حتماً غیرفعال کنید)' : 'غیرفعال و امن است.',
            ];

            // ۳. بررسی پوشه wp-content
            $content_dir = WP_CONTENT_DIR;
            if ( file_exists( $content_dir ) ) {
                $content_perms = substr( sprintf( '%o', fileperms( $content_dir ) ), -4 );
                $checks[] = [
                    'title'    => 'سطح دسترسی پوشه wp-content',
                    'status'   => in_array( $content_perms, [ '0755', '0750' ], true ) ? 'good' : 'warning',
                    'detail'   => "مجوز فعلی: $content_perms (استاندارد: 0755)",
                ];
            }

            // ۴. نسخه PHP
            $memory = ini_get( 'memory_limit' );
            $checks[] = [
                'title'    => 'نسخه PHP و محدودیت حافظه',
                'status'   => version_compare( PHP_VERSION, '7.4', '>=' ) ? 'good' : 'warning',
                'detail'   => 'نسخه PHP: ' . PHP_VERSION . ' | حافظه مجاز: ' . $memory,
            ];

            return $checks;
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
