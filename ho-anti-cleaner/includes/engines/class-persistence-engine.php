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

            // ۸. بررسی محتوای پست‌ها و صفحات (تزریق‌های EtherHiding و المنتور)
            $findings = array_merge( $findings, self::scan_database_posts( $scan_id ) );

            // ۹. بررسی فایل‌های پیکربندی وب‌سرور (.htaccess, .user.ini)
            $findings = array_merge( $findings, self::scan_server_configs( $scan_id ) );

            // ۱۰. بررسی سطوح دسترسی ناامن و تغییریافته فایل‌های حیاتی (Permissions Audit)
            $findings = array_merge( $findings, self::scan_insecure_permissions( $scan_id ) );

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

            // ج) بررسی دستکاری آدرس اصلی سایت (Site URL / Home Hijacking)
            $siteurl = get_option( 'siteurl', '' );
            $home    = get_option( 'home', '' );
            $tampered_tld_pattern = '/(?:\.ru|\.top|\.xyz|\.click|\.pw|\.cc|\.ws|ngrok|\/gate|\/evil|0x[0-9a-f]{40})/i';

            foreach ( [ 'siteurl' => $siteurl, 'home' => $home ] as $key => $val ) {
                if ( empty( $val ) || ! is_string( $val ) ) {
                    continue;
                }

                $is_suspicious_tld  = (bool) preg_match( $tampered_tld_pattern, $val );
                $trusted_url        = get_option( 'ho_anti_trusted_' . $key, '' );
                $is_domain_mismatch = ( ! empty( $trusted_url ) && parse_url( $val, PHP_URL_HOST ) !== parse_url( $trusted_url, PHP_URL_HOST ) );

                if ( $is_suspicious_tld || $is_domain_mismatch ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_SITEURL_TAMPERED',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'redirect_hijack',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_option',
                        'target_path'        => $key,
                        'evidence'           => [
                            'detail'        => "آدرس اصلی سایت ($key) در پایگاه داده به یک دامنه خارجی یا اسپم تغییر داده شده است!",
                            'current_value' => $val,
                            'trusted_value' => $trusted_url,
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

        /**
         * ۹. بررسی محتوای پست‌ها و صفحات وردپرس (تزریق‌های EtherHiding و Web3 Smart Contract C2)
         */
        public static function scan_database_posts( $scan_id ) {
            global $wpdb;
            $findings = [];

            if ( empty( $wpdb ) ) {
                return $findings;
            }

            $malware_terms = [
                'polygon-bor-rpc',
                '1rpc.io',
                '0xb29927B7D854b232D5E58CFc201866376E68C676',
                '0x2cae8ae4',
                'eth_call',
                'data-no-optimize="1"',
                'all.min.js',
                'ClickFix',
                'powershell -enc',
                'powershell.exe -w hidden',
            ];

            $like_clauses = [];
            foreach ( $malware_terms as $term ) {
                $like_clauses[] = $wpdb->prepare( "post_content LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $where_sql = implode( ' OR ', $like_clauses );

            $posts = $wpdb->get_results( "SELECT ID, post_title, post_type, post_status FROM {$wpdb->posts} WHERE {$where_sql} LIMIT 50" );

            if ( ! empty( $posts ) ) {
                foreach ( $posts as $p ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_POST_ETHERHIDING_INJECTION',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'redirect_malware',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_post',
                        'target_path'        => 'post_id:' . $p->ID,
                        'evidence'           => [
                            'post_id'   => $p->ID,
                            'title'     => $p->post_title,
                            'post_type' => $p->post_type,
                            'detail'    => "تزریق اسکریپت مخرب EtherHiding / Web3 Smart Contract در محتوای پست یا قالب المنتور",
                        ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                    ] );
                }
            }

            // بررسی متادیتای المنتور و پست‌ها در wp_postmeta
            $meta_like = [];
            foreach ( [ 'polygon-bor-rpc', '1rpc.io', '0xb29927B7D854b232D5E58CFc201866376E68C676', '0x2cae8ae4' ] as $term ) {
                $meta_like[] = $wpdb->prepare( "meta_value LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $meta_sql = implode( ' OR ', $meta_like );
            $metas = $wpdb->get_results( "SELECT meta_id, post_id, meta_key FROM {$wpdb->postmeta} WHERE {$meta_sql} LIMIT 50" );
            if ( ! empty( $metas ) ) {
                foreach ( $metas as $m ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_POSTMETA_ETHERHIDING_INJECTION',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'redirect_malware',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'database_postmeta',
                        'target_path'        => 'meta_id:' . $m->meta_id,
                        'evidence'           => [
                            'meta_id'   => $m->meta_id,
                            'post_id'   => $m->post_id,
                            'meta_key'  => $m->meta_key,
                            'detail'    => "تزریق اسکریپت مخرب EtherHiding در متادیتای المنتور یا پست ({$m->meta_key})",
                        ],
                        'severity'           => HO_Anti_Finding::SEVERITY_CRITICAL,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'recommended_action' => HO_Anti_Finding::ACTION_CLEAN_DB,
                    ] );
                }
            }

            // بررسی آپشن‌ها و ویجت‌های HTML در wp_options
            $opt_like = [];
            foreach ( [ 'polygon-bor-rpc', '1rpc.io', '0xb29927B7D854b232D5E58CFc201866376E68C676', '0x2cae8ae4' ] as $term ) {
                $opt_like[] = $wpdb->prepare( "option_value LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $opt_sql = implode( ' OR ', $opt_like );
            $opts = $wpdb->get_results( "SELECT option_name FROM {$wpdb->options} WHERE {$opt_sql} LIMIT 50" );
            if ( ! empty( $opts ) ) {
                foreach ( $opts as $o ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'DB_OPTION_ETHERHIDING_INJECTION',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'redirect_malware',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE,
                        'target_type'        => 'option',
                        'target_path'        => $o->option_name,
                        'evidence'           => [
                            'option_name' => $o->option_name,
                            'detail'      => "تزریق اسکریپت مخرب EtherHiding / Web3 C2 در تنظیمات ({$o->option_name})",
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
         * ۱۰. بررسی سطوح دسترسی ناامن و تغییریافته فایل‌های حیاتی (File Permissions Audit)
         */
        public static function scan_insecure_permissions( $scan_id ) {
            $findings = [];
            $abs_path = defined( 'ABSPATH' ) ? wp_normalize_path( ABSPATH ) : '';
            if ( empty( $abs_path ) ) {
                return $findings;
            }

            $sensitive_files = [
                $abs_path . 'wp-config.php',
                $abs_path . '.htaccess',
                $abs_path . '.user.ini',
                $abs_path . 'index.php',
                $abs_path . 'wp-login.php',
                $abs_path . 'wp-settings.php',
                $abs_path . 'wp-load.php',
                $abs_path . 'wp-admin/index.php',
            ];

            foreach ( $sensitive_files as $f ) {
                if ( ! file_exists( $f ) ) {
                    continue;
                }

                $perms = fileperms( $f );
                if ( false === $perms ) {
                    continue;
                }

                $octal = substr( sprintf( '%o', $perms ), -4 );

                // در صورتی که فایل مجوز 0666، 0777، یا قابل نوشتن همگانی (World-Writable) داشته باشد
                $is_world_writable = ( ( $perms & 0002 ) !== 0 );
                $is_danger_mode    = in_array( $octal, [ '0666', '0777', '0775', '0664' ], true );

                if ( $is_world_writable || $is_danger_mode ) {
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => 'persistence_and_database',
                        'rule_id'            => 'FILE_PERMISSIONS_INSECURE',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'permission_tampering',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_SUSPICIOUS,
                        'target_type'        => 'file',
                        'target_path'        => $f,
                        'evidence'           => [
                            'current_perms' => $octal,
                            'detail'        => "فایل حیاتی دارای سطح دسترسی ناامن ({$octal}) است و ممکن است توسط مهاجم قابل بازنویسی مجدد شده باشد.",
                        ],
                        'severity'           => HO_Anti_Finding::SEVERITY_HIGH,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                        'recommended_action' => HO_Anti_Finding::ACTION_TARGETED_REPAIR,
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
