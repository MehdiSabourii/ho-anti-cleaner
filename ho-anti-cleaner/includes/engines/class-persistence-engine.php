<?php
/**
 * Persistence & Database Security Scanner for Gravity Security & HO Anti Cleaner
 * پایش عمیق نقاط ماندگاری مهاجم: Drop-ins، تم فعال، کران‌جاب‌ها، آپشن‌های دیتابیس و کاربران مخفی
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Persistence_Engine' ) ) {

    class HO_Anti_Persistence_Engine implements HO_Anti_Detection_Adapter_Interface {

        private $last_error = '';

        public function get_engine_id() {
            return 'persistence_and_database';
        }

        public function get_engine_name() {
            return 'Persistence & Database Security Scanner';
        }

        public function get_engine_version() {
            return '2.0.0';
        }

        public function is_available() {
            global $wpdb;
            return ! empty( $wpdb );
        }

        public function get_unavailability_reason() {
            return $this->last_error ? $this->last_error : 'DATABASE_UNAVAILABLE';
        }

        /**
         * اجرای اسکن کامل نقاط ماندگاری
         */
        public function scan( array $targets = [], array $context = [] ) {
            $findings = [];
            $scan_id  = ! empty( $context['scan_id'] ) ? $context['scan_id'] : 'scan_' . date( 'Ymd_His' );

            // ۱. بررسی Drop-ins و فایل‌های خوداجرا در wp-content
            $findings = array_merge( $findings, self::scan_drop_ins( $scan_id ) );

            // ۲. بررسی Must-Use Plugins (mu-plugins)
            $findings = array_merge( $findings, self::scan_mu_plugins( $scan_id ) );

            // ۳. بررسی فایل wp-config.php و تنظیمات زمان اجرا
            $findings = array_merge( $findings, self::scan_wp_config_persistence( $scan_id ) );

            // ۴. بررسی قالب فعال (Active Theme functions.php)
            $findings = array_merge( $findings, self::scan_active_theme_persistence( $scan_id ) );

            // ۵. بررسی کاربران مشکوک و نقش‌های غیرعادی در دیتابیس
            $findings = array_merge( $findings, self::scan_database_users( $scan_id ) );

            // ۶. بررسی آپشن‌های حساس و رکوردهای autoload دیتابیس
            $findings = array_merge( $findings, self::scan_database_options( $scan_id ) );

            // ۷. بررسی وظایف زمان‌بندی‌شده WP-Cron
            $findings = array_merge( $findings, self::scan_cron_persistence( $scan_id ) );

            // ۸. بررسی فایل‌های پیکربندی وب‌سرور (.htaccess, .user.ini)
            $findings = array_merge( $findings, self::scan_server_configs( $scan_id ) );

            return $findings;
        }

        /**
         * ۱. بررسی Drop-ins
         */
        public static function scan_drop_ins( $scan_id ) {
            $findings = [];
            $drop_ins = [
                'advanced-cache.php' => 'کَش پیشرفته',
                'object-cache.php'   => 'کَش اشیاء',
                'db.php'             => 'پایگاه داده سفارشی',
                'db-error.php'       => 'صفحه خطای دیتابیس',
                'maintenance.php'    => 'حالت تعمیر و نگهداری',
                'sunrise.php'        => 'راه‌انداز چندسایته (Multisite Sunrise)',
            ];

            $content_dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content';

            foreach ( $drop_ins as $filename => $desc ) {
                $path = $content_dir . '/' . $filename;
                if ( file_exists( $path ) ) {
                    $content = @file_get_contents( $path );
                    if ( empty( $content ) ) continue;

                    // بررسی آیا فایل حاوی نشانه‌های شناخته‌شده بدافزار است
                    $has_malware = ( false !== strpos( $content, 'WP_Sys_Optimiser' ) ||
                                     false !== strpos( $content, 'xCzpFLgFPHRLRAiM' ) ||
                                     false !== strpos( $content, 'yrxc_u' ) ||
                                     preg_match( '/(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate)/i', $content ) );

                    if ( $has_malware ) {
                        $findings[] = new HO_Anti_Finding( [
                            'scan_id'            => $scan_id,
                            'engine'             => 'persistence_and_database',
                            'rule_id'            => 'DROPIN_MALICIOUS_HOOK',
                            'rule_version'       => '1.0.0',
                            'threat_category'    => 'persistence',
                            'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                            'target_type'        => 'file',
                            'target_path'        => $path,
                            'evidence'           => [ 'detail' => "درپشتی بدافزار پنهان‌شده در فایل Drop-in وردپرس ($desc: $filename)" ],
                            'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                            'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                            'local_hash'         => md5( $content ),
                            'recommended_action' => HO_Anti_Finding::ACTION_QUARANTINE,
                        ] );
                    }
                }
            }

            return $findings;
        }

        /**
         * ۲. بررسی عمیق Must-Use Plugins
         */
        public static function scan_mu_plugins( $scan_id ) {
            $findings = [];
            $mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

            if ( ! is_dir( $mu_dir ) || ! is_readable( $mu_dir ) ) {
                return $findings;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $mu_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                );

                foreach ( $iterator as $file ) {
                    if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                        $path     = $file->getRealPath();
                        $filename = $file->getFilename();
                        $content  = @file_get_contents( $path, false, null, 0, 1048576 );

                        if ( empty( $content ) ) continue;

                        $is_01_backdoor = ( 0 === strpos( $filename, '01-mu-' ) );
                        $has_assetflow  = ( false !== strpos( $content, 'WP_Sys_Optimiser' ) || false !== strpos( $content, 'Asset Flow' ) );
                        $has_rce        = ( preg_match( '/eval\s*\(\s*base64_decode/i', $content ) || preg_match( '/yrxc_u/i', $content ) );

                        if ( $is_01_backdoor || $has_assetflow || $has_rce ) {
                            $findings[] = new HO_Anti_Finding( [
                                'scan_id'            => $scan_id,
                                'engine'             => 'persistence_and_database',
                                'rule_id'            => 'MU_PLUGIN_BACKDOOR',
                                'rule_version'       => '1.0.0',
                                'threat_category'    => 'persistence',
                                'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                                'target_type'        => 'mu_plugin',
                                'target_path'        => $path,
                                'evidence'           => [
                                    'filename' => $filename,
                                    'detail'   => 'فایل درپشتی خوداجرا در پوشه Must-Use Plugins شناسایی شد.',
                                ],
                                'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                                'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                                'local_hash'         => md5( $content ),
                                'recommended_action' => HO_Anti_Finding::ACTION_QUARANTINE,
                            ] );
                        }
                    }
                }
            } catch ( Exception $e ) {
                // خطای دسترسی
            }

            return $findings;
        }

        /**
         * ۳. بررسی wp-config.php
         */
        public static function scan_wp_config_persistence( $scan_id ) {
            $findings = [];
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
                $config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( ! file_exists( $config_path ) ) {
                return $findings;
            }

            $content = @file_get_contents( $config_path );
            if ( empty( $content ) ) {
                return $findings;
            }

            // بررسی تزریق کد یا ریدایرکت‌های مشکوک در wp-config
            if ( preg_match( '/(?:eval|base64_decode|system|shell_exec|curl_exec)\s*\(/i', $content ) ) {
                // اطمینان از اینکه فراخوانی استاندارد نیست
                if ( false !== strpos( $content, 'WP_Sys_Optimiser' ) || false !== strpos( $content, 'base64_decode' ) ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'WP_CONFIG_INJECTION',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'persistence',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'file',
                        'target_path'        => $config_path,
                        'evidence'           => [ 'detail' => 'تزریق کدهای اجرایی مشکوک در فایل حیاتی wp-config.php کشف شد.' ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                        'local_hash'         => md5( $content ),
                        'recommended_action' => HO_Anti_Finding::ACTION_MANUAL_REVIEW,
                    ] );
                }
            }

            return $findings;
        }

        /**
         * ۴. بررسی قالب فعال (Active Theme functions.php)
         */
        public static function scan_active_theme_persistence( $scan_id ) {
            $findings = [];
            $theme_dir = get_stylesheet_directory();
            $functions_php = $theme_dir . '/functions.php';

            if ( file_exists( $functions_php ) && is_readable( $functions_php ) ) {
                $content = @file_get_contents( $functions_php );
                if ( ! empty( $content ) ) {
                    // بررسی ایجاد پنهانی مدیر در functions.php (الگوی مرسوم هکرها)
                    $creates_admin = preg_match( '/wp_create_user|wp_insert_user/i', $content ) &&
                                     preg_match( '/administrator/i', $content );

                    $has_malware_anchor = ( false !== strpos( $content, 'WP_Sys_Optimiser' ) || false !== strpos( $content, 'xCzpFLgFPHRLRAiM' ) );

                    if ( $creates_admin || $has_malware_anchor ) {
                        $findings[] = new HO_Anti_Finding( [
                            'scan_id'            => $scan_id,
                            'engine'             => 'persistence_and_database',
                            'rule_id'            => 'THEME_ROGUE_ADMIN_CREATOR',
                            'rule_version'       => '1.0.0',
                            'threat_category'    => 'persistence',
                            'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                            'target_type'        => 'theme_file',
                            'target_path'        => $functions_php,
                            'evidence'           => [ 'detail' => 'کد تزریق‌شده در functions.php قالب فعال برای ساخت ادمین درپشتی یا اجرای بدافزار' ],
                            'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                            'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                            'local_hash'         => md5( $content ),
                            'recommended_action' => HO_Anti_Finding::ACTION_MANUAL_REVIEW,
                        ] );
                    }
                }
            }

            return $findings;
        }

        /**
         * ۵. بررسی کاربران مشکوک و نقش‌ها در دیتابیس
         */
        public static function scan_database_users( $scan_id ) {
            global $wpdb;
            $findings = [];

            if ( empty( $wpdb ) ) return $findings;

            $users = $wpdb->get_results( "SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users}" );
            if ( empty( $users ) ) return $findings;

            foreach ( $users as $u ) {
                $is_sys_pattern = (bool) preg_match( '/^sys_[a-f0-9]{8}$/i', $u->user_login );
                $is_noreply     = ( false !== strpos( $u->user_email, 'noreply@' ) );

                $caps = get_user_meta( $u->ID, $wpdb->prefix . 'capabilities', true );
                $is_admin = is_array( $caps ) && isset( $caps['administrator'] ) && $caps['administrator'];

                if ( $is_sys_pattern || ( $is_noreply && $is_admin ) ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_ROGUE_BACKDOOR_ADMIN',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'unauthorized_access',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_user',
                        'target_path'        => 'user_id:' . $u->ID,
                        'evidence'           => [
                            'user_login' => $u->user_login,
                            'user_email' => $u->user_email,
                            'registered' => $u->user_registered,
                            'is_admin'   => $is_admin,
                        ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                    ] );
                }
            }

            return $findings;
        }

        /**
         * ۶. بررسی آپشن‌های مشکوک و جداول نامعتبر دیتابیس
         */
        public static function scan_database_options( $scan_id ) {
            global $wpdb;
            $findings = [];

            if ( empty( $wpdb ) ) return $findings;

            // الف) آپشن‌های شناخته‌شده بدافزار
            $malicious_opts = [ 'jsonmetafield', 'sub_valid_adm', 'sub_valid_adm1' ];
            foreach ( $malicious_opts as $opt ) {
                $val = get_option( $opt, null );
                if ( null !== $val ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_MALICIOUS_OPTION',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'persistence',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_option',
                        'target_path'        => $opt,
                        'evidence'           => [ 'detail' => "کلید مخرب ردگیری و ماندگاری بدافزار در جدول wp_options ($opt)" ],
                        'severity'           => HO_Anti_Finding::SEVERITY_HIGH,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                    ] );
                }
            }

            // ب) جداول اختصاصی بدافزار (sys_av_*)
            $db_prefix = $wpdb->prefix;
            $tables = $wpdb->get_col( "SHOW TABLES LIKE '{$db_prefix}sys_av_%'" );
            if ( ! empty( $tables ) ) {
                foreach ( $tables as $tbl ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_MALICIOUS_TABLE',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'persistence',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_table',
                        'target_path'        => $tbl,
                        'evidence'           => [ 'detail' => "جدول اختصاصی ردگیری و آمار مهاجم در پایگاه داده ($tbl)" ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                    ] );
                }
            }

            return $findings;
        }

        /**
         * ۷. بررسی هوک‌های WP-Cron
         */
        public static function scan_cron_persistence( $scan_id ) {
            $findings = [];
            $crons = _get_cron_array();

            if ( empty( $crons ) || ! is_array( $crons ) ) {
                return $findings;
            }

            $suspicious_names = [ 'av_', 'sys_', 'opt_', 'check_version_update', 'wp_sys', 'assetflow' ];

            foreach ( $crons as $timestamp => $hooks ) {
                foreach ( $hooks as $hook => $data ) {
                    foreach ( $suspicious_names as $needle ) {
                        if ( false !== stripos( $hook, $needle ) ) {
                            $has_action = has_action( $hook );
                            $findings[] = new HO_Anti_Finding( [
                                'scan_id'            => $scan_id,
                                'engine'             => 'persistence_and_database',
                                'rule_id'            => 'CRON_SUSPICIOUS_HOOK',
                                'rule_version'       => '1.0.0',
                                'threat_category'    => 'persistence',
                                'classification'     => HO_Anti_Finding::CLASSIFICATION_SUSPICIOUS,
                                'target_type'        => 'cron_job',
                                'target_path'        => $hook,
                                'evidence'           => [
                                    'hook'        => $hook,
                                    'has_action'  => (bool) $has_action,
                                    'scheduled'   => date( 'Y-m-d H:i:s', $timestamp ),
                                ],
                                'severity'           => HO_Anti_Finding::SEVERITY_MEDIUM,
                                'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                                'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                            ] );
                            break;
                        }
                    }
                }
            }

            return $findings;
        }

        /**
         * ۸. بررسی پیکربندی وب‌سرور (.htaccess, .user.ini)
         */
        public static function scan_server_configs( $scan_id ) {
            $findings = [];
            $configs = [
                ABSPATH . '.htaccess',
                ABSPATH . '.user.ini',
            ];

            foreach ( $configs as $cfg ) {
                if ( ! file_exists( $cfg ) || ! is_readable( $cfg ) ) continue;

                $content = @file_get_contents( $cfg );
                if ( empty( $content ) ) continue;

                // بررسی دستورات مشکوک auto_prepend_file یا auto_append_file
                if ( preg_match( '/(?:auto_prepend_file|auto_append_file)\s*=/i', $content ) ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'SERVER_CONFIG_AUTO_PREPEND',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'persistence',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'file',
                        'target_path'        => $cfg,
                        'evidence'           => [ 'detail' => 'دستور auto_prepend_file یا auto_append_file در فایل پیکربندی سرور یافت شد (اجرای اجباری کد قبل/بعد از هر درخواست).' ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                        'local_hash'         => md5( $content ),
                        'recommended_action' => HO_Anti_Finding::ACTION_MANUAL_REVIEW,
                    ] );
                }
            }

            return $findings;
        }
    }

    if ( ! class_exists( 'Gravity_Persistence_Engine' ) ) {
        class_alias( 'HO_Anti_Persistence_Engine', 'Gravity_Persistence_Engine' );
    }
}
