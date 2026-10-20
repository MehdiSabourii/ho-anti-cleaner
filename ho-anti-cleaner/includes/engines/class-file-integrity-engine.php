<?php
/**
 * File Integrity Engine for Gravity Security & HO Anti Cleaner
 * موتور اعتبارسنجی یکپارچگی فایل‌های هسته، مقایسه با مرجع رسمی و ثبت تفاوت‌ها (Diff)
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_File_Integrity_Engine' ) ) {

    class HO_Anti_File_Integrity_Engine implements HO_Anti_Detection_Adapter_Interface {

        private $last_error = '';

        public function get_engine_id() {
            return 'core_integrity';
        }

        public function get_engine_name() {
            return 'Core File Integrity Engine';
        }

        public function get_engine_version() {
            return '1.0.0';
        }

        public function is_available() {
            return function_exists( 'wp_remote_get' );
        }

        public function get_unavailability_reason() {
            return $this->last_error ? $this->last_error : 'HTTP_TRANSPORT_UNAVAILABLE';
        }

        /**
         * دریافت چکسام‌های رسمی نسخه جاری وردپرس از API رسمی WordPress.org
         *
         * @param string $version نسخه وردپرس
         * @return array|false
         */
        public static function get_official_core_checksums( $version = '' ) {
            if ( empty( $version ) ) {
                global $wp_version;
                $version = ! empty( $wp_version ) ? $wp_version : get_bloginfo( 'version' );
            }

            // بررسی کش ترنزینت جهت جلوگیری از ارسال درخواست‌های تکراری
            $cache_key = 'ho_anti_core_checksums_' . md5( (string) $version );
            $cached = get_transient( $cache_key );
            if ( false !== $cached && is_array( $cached ) ) {
                return $cached;
            }

            $locale = function_exists( 'get_locale' ) ? get_locale() : 'en_US';
            $url    = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";

            $response = wp_remote_get( $url, [
                'timeout'    => 15,
                'user-agent' => 'Gravity-Security-File-Integrity/' . HO_ANTI_VERSION,
            ] );

            if ( is_wp_error( $response ) ) {
                // تلاش مجدد با زبان انگلیسی پیش‌فرض
                $fallback_url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US";
                $response = wp_remote_get( $fallback_url, [ 'timeout' => 15 ] );
                if ( is_wp_error( $response ) ) {
                    return false;
                }
            }

            $body = wp_remote_retrieve_body( $response );
            $json = json_decode( $body, true );

            if ( empty( $json ) || ! isset( $json['checksums'] ) || ! is_array( $json['checksums'] ) ) {
                return false;
            }

            // ذخیره در کش به مدت ۲۴ ساعت
            $day_seconds = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
            set_transient( $cache_key, $json['checksums'], $day_seconds );

            return $json['checksums'];
        }

        /**
         * اجرای اسکن کامل یکپارچگی فایل‌های هسته
         *
         * @param array $targets اهداف (در صورت خالی بودن کل ABSPATH مد نظر است)
         * @param array $context زمینه اسکن
         * @return HO_Anti_Finding[]
         */
        public function scan( array $targets = [], array $context = [] ) {
            global $wp_version;
            $version   = ! empty( $wp_version ) ? $wp_version : get_bloginfo( 'version' );
            $scan_id   = ! empty( $context['scan_id'] ) ? $context['scan_id'] : 'scan_' . date( 'Ymd_His' );
            $checksums = self::get_official_core_checksums( $version );

            $findings = [];

            if ( false === $checksums ) {
                $this->last_error = 'REFERENCE_UNAVAILABLE';
                $findings[] = new HO_Anti_Finding( [
                    'scan_id'            => $scan_id,
                    'engine'             => $this->get_engine_id(),
                    'rule_id'            => 'CORE_CHECKSUMS_API_BLOCKED',
                    'rule_version'       => '1.0.0',
                    'threat_category'    => 'network_connectivity',
                    'classification'     => HO_Anti_Finding::CLASSIFICATION_SUSPICIOUS,
                    'target_type'        => 'api_endpoint',
                    'target_path'        => 'api.wordpress.org/core/checksums/1.0/',
                    'evidence'           => [ 'error' => 'امکان دریافت چکسام‌های رسمی از WordPress.org فراهم نیست (قطعی اینترنت، فیلترینگ یا عدم پاسخ سرور).' ],
                    'severity'           => HO_Anti_Finding::SEVERITY_MEDIUM,
                    'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                    'recommended_action' => HO_Anti_Finding::ACTION_MANUAL_REVIEW,
                    'metadata'           => [ 'status' => 'BLOCKED_ENVIRONMENT' ],
                ] );
                return $findings;
            }

            $abs_path = wp_normalize_path( ABSPATH );

            // ۱. بررسی فایل‌های موجود در لیست رسمی (فایل‌های تغییرکرده و فایل‌های حذف‌شده)
            foreach ( $checksums as $rel_path => $expected_hash ) {
                // مستثنی‌سازی فایل‌های زبان
                if ( 0 === strpos( $rel_path, 'wp-content/' ) ) {
                    continue;
                }

                $full_path = $abs_path . $rel_path;

                if ( ! file_exists( $full_path ) ) {
                    // فایل هسته حذف شده است
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => $this->get_engine_id(),
                        'rule_id'            => 'CORE_FILE_MISSING',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'file_tampering',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_FILE_CHANGE,
                        'target_type'        => 'core_file',
                        'target_path'        => $full_path,
                        'evidence'           => [ 'detail' => 'فایل استاندارد هسته وردپرس از روی سرور حذف شده است.' ],
                        'severity'           => HO_Anti_Finding::SEVERITY_HIGH,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_CONFIRMED,
                        'local_hash'         => null,
                        'trusted_reference'  => [
                            'source'        => 'api.wordpress.org',
                            'version'       => $version,
                            'expected_hash' => $expected_hash,
                        ],
                        'recommended_action' => HO_Anti_Finding::ACTION_RESTORE_TRUSTED,
                    ] );
                    continue;
                }

                // محاسبه هش فایل محلی
                $local_hash = md5_file( $full_path );
                if ( $local_hash !== $expected_hash ) {
                    // فایل تغییر کرده است
                    $findings[] = new HO_Anti_Finding( [
                        'scan_id'            => $scan_id,
                        'engine'             => $this->get_engine_id(),
                        'rule_id'            => 'CORE_FILE_MODIFIED',
                        'rule_version'       => '1.0.0',
                        'threat_category'    => 'file_tampering',
                        'classification'     => HO_Anti_Finding::CLASSIFICATION_FILE_CHANGE,
                        'target_type'        => 'core_file',
                        'target_path'        => $full_path,
                        'evidence'           => [
                            'detail'        => 'هش فایل با نسخه رسمی وردپرس مغایرت دارد (احتمال تزریق کد یا دستکاری).',
                            'local_hash'    => $local_hash,
                            'expected_hash' => $expected_hash,
                        ],
                        'severity'           => HO_Anti_Finding::SEVERITY_HIGH,
                        'confidence'         => HO_Anti_Finding::CONFIDENCE_HIGH,
                        'local_hash'         => $local_hash,
                        'trusted_reference'  => [
                            'source'        => 'api.wordpress.org',
                            'version'       => $version,
                            'expected_hash' => $expected_hash,
                        ],
                        'recommended_action' => HO_Anti_Finding::ACTION_RESTORE_TRUSTED,
                        'metadata'           => [
                            'relative_path' => $rel_path,
                            'file_size'     => filesize( $full_path ),
                        ],
                    ] );
                }
            }

            // ۲. بررسی فایل‌های PHP اضافی و ناشناخته در پوشه‌های اختصاصی هسته (wp-admin و wp-includes)
            $core_dirs = [
                $abs_path . 'wp-admin',
                $abs_path . WPINC,
            ];

            foreach ( $core_dirs as $core_dir ) {
                if ( ! is_dir( $core_dir ) ) continue;

                try {
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator( $core_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                    );

                    foreach ( $iterator as $file ) {
                        if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                            $path     = wp_normalize_path( $file->getRealPath() );
                            $rel_path = ltrim( substr( $path, strlen( $abs_path ) ), '/' );

                            // اگر این فایل در لیست چکسام‌های رسمی وردپرس نباشد
                            if ( ! isset( $checksums[ $rel_path ] ) ) {
                                $local_hash = md5_file( $path );
                                $findings[] = new HO_Anti_Finding( [
                                    'scan_id'            => $scan_id,
                                    'engine'             => $this->get_engine_id(),
                                    'rule_id'            => 'CORE_DIR_UNREFERENCED_PHP',
                                    'rule_version'       => '1.0.0',
                                    'threat_category'    => 'malware',
                                    'classification'     => HO_Anti_Finding::CLASSIFICATION_SUSPICIOUS,
                                    'target_type'        => 'core_file',
                                    'target_path'        => $path,
                                    'evidence'           => [
                                        'detail' => 'فایل PHP ناشناخته و فاقد مرجع رسمی در پوشه هسته وردپرس یافت شد.',
                                        'file'   => $file->getFilename(),
                                    ],
                                    'severity'           => HO_Anti_Finding::SEVERITY_HIGH,
                                    'confidence'         => HO_Anti_Finding::CONFIDENCE_MEDIUM,
                                    'local_hash'         => $local_hash,
                                    'recommended_action' => HO_Anti_Finding::ACTION_QUARANTINE,
                                ] );
                            }
                        }
                    }
                } catch ( Exception $e ) {
                    // در صورت خطای دسترسی
                }
            }

            return $findings;
        }

        /**
         * تولید گزارش تفاوت (Diff) بین فایل محلی و نسخه رسمی وردپرس
         *
         * @param string $file_path مسیر کامل فایل محلی
         * @return array [ 'success' => bool, 'diff' => string, 'added_lines' => int, 'removed_lines' => int ]
         */
        public static function get_file_diff( $file_path ) {
            global $wp_version;
            $version   = ! empty( $wp_version ) ? $wp_version : get_bloginfo( 'version' );
            $abs_path  = wp_normalize_path( ABSPATH );
            $norm_path = wp_normalize_path( $file_path );

            if ( 0 !== strpos( $norm_path, $abs_path ) ) {
                return [ 'success' => false, 'message' => 'فایل خارج از ریشه وردپرس است.' ];
            }

            $rel_path = ltrim( substr( $norm_path, strlen( $abs_path ) ), '/' );

            // دریافت فایل رسمی
            $remote_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/" . $rel_path;
            $response   = wp_remote_get( $remote_url, [ 'timeout' => 15 ] );

            if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
                return [ 'success' => false, 'message' => 'امکان دریافت فایل رسمی برای مقایسه وجود ندارد.' ];
            }

            $official_code = wp_remote_retrieve_body( $response );
            $local_code    = @file_get_contents( $file_path );

            if ( false === $local_code ) {
                return [ 'success' => false, 'message' => 'امکان خواندن فایل محلی وجود ندارد.' ];
            }

            $official_lines = explode( "\n", str_replace( "\r\n", "\n", $official_code ) );
            $local_lines    = explode( "\n", str_replace( "\r\n", "\n", $local_code ) );

            $diff_output   = [];
            $added_count   = 0;
            $removed_count = 0;

            // مقایسه خط به خط ساده و خوانا
            $max_lines = max( count( $official_lines ), count( $local_lines ) );
            for ( $i = 0; $i < $max_lines; $i++ ) {
                $off_line = isset( $official_lines[ $i ] ) ? $official_lines[ $i ] : null;
                $loc_line = isset( $local_lines[ $i ] ) ? $local_lines[ $i ] : null;

                if ( $off_line !== $loc_line ) {
                    if ( null !== $off_line && null === $loc_line ) {
                        $diff_output[] = "- [خط " . ($i + 1) . "] " . $off_line;
                        $removed_count++;
                    } elseif ( null === $off_line && null !== $loc_line ) {
                        $diff_output[] = "+ [خط " . ($i + 1) . "] " . $loc_line;
                        $added_count++;
                    } else {
                        $diff_output[] = "- [خط " . ($i + 1) . "] " . $off_line;
                        $diff_output[] = "+ [خط " . ($i + 1) . "] " . $loc_line;
                        $removed_count++;
                        $added_count++;
                    }
                }
            }

            return [
                'success'       => true,
                'diff'          => implode( "\n", array_slice( $diff_output, 0, 100 ) ), // نمایش حداکثر ۱۰۰ خط تفاوت
                'added_lines'   => $added_count,
                'removed_lines' => $removed_count,
                'total_diff'    => count( $diff_output ),
            ];
        }
    }

    if ( ! class_exists( 'Gravity_File_Integrity_Engine' ) ) {
        class_alias( 'HO_Anti_File_Integrity_Engine', 'Gravity_File_Integrity_Engine' );
    }
}
