<?php
/**
 * Scanner Engine for HO Anti Cleaner
 * موتور اسکن عمیق، تحلیل اکتشافی و شناسایی کدهای مخرب
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Scanner' ) ) {

    class HO_Anti_Scanner {

        private static function get_signatures() {
            return [
                'class_name'     => 'WP_' . 'Sys_' . 'Optimiser',
                'goto_anchor'    => 'xCzpFLgF' . 'PHRLRAiM',
                'const_anchor'   => 'AV_' . 'COMPLETED',
                'func_anchor'    => 'show_advanced_' . 'plugins',
                'label_anchor'   => 'FDlmxj3D' . '5L76GWZ3',
                'label_anchor2'  => 'pLWYN1lw0' . '1T8JF5A',
                'label_anchor3'  => 'swCXnNWQd' . '89vfQWL',
                'encoded_mu'     => "\60\x31\x2d\155\165\x2d",
                'header_anchor'  => 'Asset' . ' Flow',
                'author_anchor'  => 'Torq' . 'Soft',
                'option_anchor'  => 'json' . 'metafield',
                'option_anchor2' => 'sub_valid' . '_adm',
                'table_anchor'   => 'wp_sys_' . 'av_',
                'cookie_locker'  => 'yrxc_u',
                'gatekeeper_md5' => 'while(md5(md5(',
                'hash_locker'    => 'fe' . '98788c' . '6cf41c9f48e53cc93' . '245c23c',
            ];
        }

        public static function perform_full_scan() {
            @ini_set( 'memory_limit', '512M' );
            @set_time_limit( 300 );

            global $wpdb;

            $results = [
                'timestamp'        => current_time( 'mysql' ),
                'options'          => [],
                'tables'           => [],
                'hidden_users'     => [],
                'mu_plugins'       => [],
                'infected_files'   => [],
                'uploads_php'      => [],
                'stats'            => [
                    'total_files_scanned' => 0,
                    'threats_count'       => 0,
                ],
            ];

            // ۱. بررسی جدول تنظیمات (wp_options)
            $malicious_options = [ 'jsonmetafield', 'sub_valid_adm', 'sub_valid_adm1' ];
            foreach ( $malicious_options as $opt_name ) {
                $val = get_option( $opt_name, null );
                if ( null !== $val ) {
                    $preview = is_scalar( $val ) ? (string) $val : json_encode( $val );
                    if ( strlen( $preview ) > 120 ) {
                        $preview = function_exists( 'mb_substr' ) ? mb_substr( $preview, 0, 120 ) . '...' : substr( $preview, 0, 120 ) . '...';
                    }
                    $results['options'][] = [
                        'option_name' => $opt_name,
                        'value'       => $preview,
                        'severity'    => 'high',
                    ];
                    $results['stats']['threats_count']++;
                }
            }

            // ۲. بررسی جداول مخرب دیتابیس (wp_sys_av_*)
            $db_prefix = $wpdb->prefix;
            $matched_tables = $wpdb->get_col( "SHOW TABLES LIKE '{$db_prefix}sys_av_%'" );
            if ( ! empty( $matched_tables ) ) {
                foreach ( $matched_tables as $tbl ) {
                    $rows = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$tbl}`" );
                    $results['tables'][] = [
                        'table_name' => $tbl,
                        'row_count'  => $rows,
                        'severity'   => 'critical',
                    ];
                    $results['stats']['threats_count']++;
                }
            }

            // ۳. بررسی کاربران مخفی (مستقیم از دیتابیس)
            $users_sql = "SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users}";
            $raw_users = $wpdb->get_results( $users_sql );
            if ( ! empty( $raw_users ) ) {
                foreach ( $raw_users as $u ) {
                    $is_sys_pattern = (bool) preg_match( '/^sys_[a-f0-9]{8}$/i', $u->user_login );
                    $is_noreply     = ( false !== strpos( $u->user_email, 'noreply@' ) );

                    $caps = get_user_meta( $u->ID, $wpdb->prefix . 'capabilities', true );
                    $is_admin = is_array( $caps ) && isset( $caps['administrator'] ) && $caps['administrator'];

                    if ( $is_sys_pattern || ( $is_noreply && $is_admin ) ) {
                        $results['hidden_users'][] = [
                            'ID'         => $u->ID,
                            'user_login' => $u->user_login,
                            'user_email' => $u->user_email,
                            'registered' => $u->user_registered,
                            'is_admin'   => $is_admin,
                            'severity'   => 'critical',
                        ];
                        $results['stats']['threats_count']++;
                    }
                }
            }

            // ۴. بررسی دقیق، بازگشتی و عمیق پوشه Must-Use Plugins (WPMU_PLUGIN_DIR)
            self::scan_mu_plugins_deep( $results );

            // ۵. اسکن عمیق فایل‌های wp-content
            $content_dir = WP_CONTENT_DIR;
            self::scan_directory_files( $content_dir, $results );

            // ۶. اسکن تمامی فایل‌های PHP ریشه وردپرس (از جمله wp-login.php، index.php و...)
            self::scan_root_files( ABSPATH, $results );

            // ۷. اسکن پوشه‌های هسته wp-admin و wp-includes
            if ( defined( 'ABSPATH' ) ) {
                self::scan_core_directory( ABSPATH . 'wp-admin', $results );
                self::scan_core_directory( ABSPATH . WPINC, $results );
            }

            return $results;
        }

        /**
         * اسکن عمیق و بازگشتی پوشه Must-Use Plugins
         */
        private static function scan_mu_plugins_deep( &$results ) {
            $mu_dirs = array_unique( [
                defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
                WP_CONTENT_DIR . '/mu-plugins',
            ] );

            foreach ( $mu_dirs as $mu_dir ) {
                if ( ! is_dir( $mu_dir ) || ! is_readable( $mu_dir ) ) {
                    continue;
                }

                try {
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator( $mu_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                    );

                    foreach ( $iterator as $file ) {
                        if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                            $full_path = $file->getRealPath();
                            $filename  = $file->getFilename();

                            $content = @file_get_contents( $full_path, false, null, 0, 2097152 );
                            if ( empty( $content ) ) {
                                continue;
                            }

                            $matched_sig = self::check_content_signatures( $content );
                            $is_01_mu    = ( false !== strpos( $filename, '01-mu-' ) );
                            $is_asset    = ( false !== stripos( $content, 'Asset Flow' ) || false !== stripos( $filename, 'asset-flow' ) );

                            if ( $is_01_mu || $is_asset || ! empty( $matched_sig ) ) {
                                $rel = str_replace( [ ABSPATH, '\\' ], [ '', '/' ], $full_path );

                                $reason = ! empty( $matched_sig ) 
                                    ? implode( ' | ', $matched_sig ) 
                                    : ( $is_01_mu ? 'الگوی نام درپشتی (01-mu-)' : 'فایل مشکوک Asset Flow در mu-plugins' );

                                $results['mu_plugins'][] = [
                                    'filename' => $filename,
                                    'path'     => $full_path,
                                    'relative' => $rel,
                                    'reason'   => $reason,
                                    'severity' => 'critical',
                                ];
                                $results['stats']['threats_count']++;
                            }
                        }
                    }
                } catch ( Exception $e ) {
                    // در صورت خطای دسترسی
                }
            }
        }

        public static function check_content_signatures( $content ) {
            $hits = [];
            if ( empty( $content ) ) {
                return $hits;
            }

            $sigs = self::get_signatures();

            if ( false !== strpos( $content, $sigs['class_name'] ) ) {
                $hits[] = 'کلاس بدافزار WP_Sys_Optimiser';
            }
            if ( false !== strpos( $content, $sigs['goto_anchor'] ) ) {
                $hits[] = 'برچسب انحصاری goto xCzpFLgFPHRLRAiM';
            }
            if ( false !== strpos( $content, $sigs['const_anchor'] ) ) {
                $hits[] = 'ثابت AV_COMPLETED';
            }
            if ( false !== strpos( $content, $sigs['label_anchor'] ) ) {
                $hits[] = 'برچسب انحصاری FDlmxj3D5L76GWZ3';
            }
            if ( false !== strpos( $content, $sigs['label_anchor2'] ) ) {
                $hits[] = 'برچسب انحصاری pLWYN1lw01T8JF5A';
            }
            if ( false !== strpos( $content, $sigs['label_anchor3'] ) ) {
                $hits[] = 'برچسب انحصاری swCXnNWQd89vfQWL';
            }
            if ( false !== stripos( $content, 'Plugin Name: ' . 'Asset Flow' ) ) {
                $hits[] = 'عنوان بدافزار Asset Flow';
            }
            if ( false !== stripos( $content, $sigs['author_anchor'] ) ) {
                $hits[] = 'سازنده جعلی TorqSoft';
            }
            if ( false !== strpos( $content, $sigs['encoded_mu'] ) || false !== strpos( $content, '01-mu-' ) ) {
                $hits[] = 'کپی‌کننده درپشتی 01-mu-';
            }
            if ( false !== strpos( $content, $sigs['option_anchor'] ) ) {
                $hits[] = 'آپشن مخرب jsonmetafield';
            }
            if ( false !== strpos( $content, $sigs['option_anchor2'] ) ) {
                $hits[] = 'آپشن مخرب sub_valid_adm';
            }
            if ( false !== strpos( $content, $sigs['table_anchor'] ) ) {
                $hits[] = 'جدول اختصاصی wp_sys_av_';
            }
            if ( false !== strpos( $content, $sigs['func_anchor'] ) && false !== strpos( $content, 'all_plugins' ) ) {
                $hits[] = 'هوک‌های مخفی‌سازی افزونه‌ها';
            }

            // امضاهای جدید: گیت‌کیپر مسدودساز صفحه لاگین و کوکی هکر
            if ( false !== strpos( $content, $sigs['cookie_locker'] ) ) {
                $hits[] = 'کوکی مسدودساز صفحه لاگین (yrxc_u)';
            }
            if ( preg_match( '/while\s*\(\s*md5\s*\(\s*md5\s*\(/i', $content ) ) {
                $hits[] = 'گیت‌کیپر مسدودساز ورود (while double-md5 die)';
            }
            if ( false !== strpos( $content, 'fe98788c6cf41c9f48e53cc93245c23c' ) || false !== strpos( $content, '98788c' ) ) {
                $hits[] = 'هش انحصاری مهاجم در گیت‌کیپر (fe98788c...)';
            }

            return $hits;
        }

        private static function scan_directory_files( $dir, &$results ) {
            if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
                return;
            }

            $items = @scandir( $dir );
            if ( ! $items ) {
                return;
            }

            $this_plugin_dir = defined( 'HO_ANTI_PLUGIN_DIR' ) ? realpath( HO_ANTI_PLUGIN_DIR ) : '';

            foreach ( $items as $item ) {
                if ( $item === '.' || $item === '..' ) continue;

                $full_path = $dir . DIRECTORY_SEPARATOR . $item;

                if ( false !== strpos( $full_path, 'wp-assetflow-cleaner' ) || false !== strpos( $full_path, 'ho-anti-cleaner' ) ) {
                    continue;
                }

                if ( ! empty( $this_plugin_dir ) && ( $full_path === $this_plugin_dir || 0 === strpos( $full_path, $this_plugin_dir . DIRECTORY_SEPARATOR ) ) ) {
                    continue;
                }

                if ( is_dir( $full_path ) ) {
                    if ( in_array( $item, [ 'cache', 'node_modules', 'vendor', 'wflogs' ], true ) ) {
                        continue;
                    }

                    if ( $item === 'uploads' ) {
                        self::scan_uploads_for_stray_php( $full_path, $results );
                        continue;
                    }

                    if ( $item === 'mu-plugins' ) {
                        continue;
                    }

                    self::scan_directory_files( $full_path, $results );
                } elseif ( is_file( $full_path ) && pathinfo( $full_path, PATHINFO_EXTENSION ) === 'php' ) {
                    $results['stats']['total_files_scanned']++;
                    self::inspect_single_php_file( $full_path, $results );
                }
            }
        }

        /**
         * اسکن سریع پوشه‌های اصلی وردپرس (wp-admin و wp-includes)
         */
        private static function scan_core_directory( $dir, &$results ) {
            if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
                return;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
                );

                foreach ( $iterator as $file ) {
                    if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                        $full_path = $file->getRealPath();
                        $results['stats']['total_files_scanned']++;
                        self::inspect_single_php_file( $full_path, $results );
                    }
                }
            } catch ( Exception $e ) {
                // عبور در صورت خطا در دسترسی
            }
        }

        /**
         * موتور تحلیل اکتشافی برای شناسایی وب‌شل‌ها و تهدیدات عمومی
         */
        public static function check_generic_heuristics( $content, $full_path = '' ) {
            $hits = [];
            if ( empty( $content ) ) {
                return $hits;
            }

            // ۱. ارزیابی مستقیم ورودی‌های خطرناک با توابع دکد (eval + base64/gzinflate)
            if ( preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content ) ) {
                $hits[] = 'تزریق و اجرای کد مخفی (eval + base64/gzinflate)';
            }

            // ۲. اجرای مستقیم دستورات سرور با ورودی متغیر کاربر (RCE Web Shell)
            if ( preg_match( '/(?:assert|passthru|shell_exec|system|popen|proc_open)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/i', $content ) ) {
                $hits[] = 'اجرای مستقیم دستورات سرور (Web Shell RCE)';
            }

            // ۳. فراخوانی دینامیک متغیر توابع مخرب
            if ( preg_match( '/\$(?:_POST|_GET|_REQUEST)\[.+\]\s*\(\s*\$(?:_POST|_GET|_REQUEST)/i', $content ) ) {
                $hits[] = 'فراخوانی دینامیک درپشتی (Variable Function Backdoor)';
            }

            // ۴. شناسایی هدرها و امضاهای وب‌شل‌های معروف
            $known_shells = [
                'c99shell'    => 'وب‌شل شناخته‌شده c99',
                'r57shell'    => 'وب‌شل شناخته‌شده r57',
                'WSO_VERSION' => 'وب‌شل حرفه‌ای WSO',
                'FilesMan'    => 'اسکریپت مخرب مدیریت فایل FilesMan',
                'b374k'       => 'وب‌شل خطرناک b374k',
                'ALFA_DATA'   => 'وب‌شل پیشرفته Alfa Shell',
                'IndoXploit'  => 'اسکریپت نفوذ IndoXploit',
            ];
            foreach ( $known_shells as $sig => $desc ) {
                if ( false !== stripos( $content, $sig ) ) {
                    $hits[] = $desc;
                }
            }

            // ۵. رشته‌های طولانی هگزادسیمال پیوسته
            if ( preg_match( '/(?:\\\\x[0-9a-f]{2}){40,}/i', $content ) ) {
                $hits[] = 'کدگذاری مشکوک هگزادسیمال متوالی (Hex Obfuscation)';
            }

            // ۶. اسکریپت‌های تزریق ریدایرکت مخرب به دامنه‌های اسپم
            if ( preg_match( '/<script[^>]*src=[\'"]https?:\/\/[^\'"]*(?:\.ru|\.top|\.xyz|\.click|\.pw)[^\'"]*[\'"]/i', $content ) ) {
                $hits[] = 'تزریق ریدایرکت مخرب جاوااسکریپت به دامنه‌های اسپم';
            }

            return $hits;
        }

        private static function inspect_single_php_file( $full_path, &$results ) {
            $size = filesize( $full_path );
            if ( $size <= 0 ) {
                return;
            }

            $head_chunk = @file_get_contents( $full_path, false, null, 0, min( 6144, $size ) );
            $tail_chunk = '';
            if ( $size > 6144 ) {
                $offset = max( 0, $size - 16384 );
                $tail_chunk = @file_get_contents( $full_path, false, null, $offset, 16384 );
            }

            $combined = $head_chunk . ' ' . $tail_chunk;
            $matched_sigs = self::check_content_signatures( $combined );
            $matched_heuristics = self::check_generic_heuristics( $combined, $full_path );

            $all_hits = array_merge( $matched_sigs, $matched_heuristics );

            if ( ! empty( $all_hits ) ) {
                $is_injected_top = false;
                $is_injected_bottom = false;
                $is_assetflow = ! empty( $matched_sigs );

                // بررسی تزریق در بالای فایل (Header Gatekeeper)
                if ( class_exists( 'HO_Anti_Protection' ) && HO_Anti_Protection::has_header_malware( $head_chunk ) ) {
                    $is_injected_top = true;
                }

                // بررسی تزریق در انتهای فایل (Bottom)
                $opt_needle = 'WP_' . 'Sys_' . 'Optimiser';
                $goto_needle = 'xCzpFLgF' . 'PHRLRAiM';
                if ( false !== strpos( $tail_chunk, $opt_needle ) || false !== strpos( $tail_chunk, $goto_needle ) ) {
                    if ( $size > 8192 && false === strpos( $head_chunk, $opt_needle ) ) {
                        $is_injected_bottom = true;
                    }
                }

                $relative_path = str_replace( [ ABSPATH, '\\' ], [ '', '/' ], $full_path );
                $size_str = function_exists( 'size_format' ) ? size_format( $size ) : ( round( $size / 1024, 2 ) . ' KB' );

                $results['infected_files'][] = [
                    'path'               => $full_path,
                    'relative'           => $relative_path,
                    'size'               => $size_str,
                    'signatures'         => implode( ' | ', $all_hits ),
                    'is_injected_top'    => $is_injected_top,
                    'is_injected_bottom' => $is_injected_bottom,
                    'is_assetflow'       => $is_assetflow,
                    'is_writable'        => is_writable( $full_path ),
                    'severity'           => 'critical',
                ];
                $results['stats']['threats_count']++;
            }
        }

        private static function scan_uploads_for_stray_php( $uploads_dir, &$results ) {
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                );

                foreach ( $iterator as $file ) {
                    if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                        $full_path = $file->getRealPath();

                        if ( false !== strpos( $full_path, 'afc-quarantine-backups' ) ) {
                            continue;
                        }

                        if ( 'index.php' === strtolower( $file->getFilename() ) && $file->getSize() < 80 ) {
                            $check = trim( (string) @file_get_contents( $full_path ) );
                            if ( empty( $check ) || false !== stripos( $check, 'Silence is golden' ) ) {
                                continue;
                            }
                        }

                        $rel = str_replace( [ ABSPATH, '\\' ], [ '', '/' ], $full_path );
                        $size = $file->getSize();

                        $head = @file_get_contents( $full_path, false, null, 0, min( 6144, $size ) );
                        $tail = '';
                        if ( $size > 6144 ) {
                            $tail = @file_get_contents( $full_path, false, null, max( 0, $size - 16384 ), 16384 );
                        }
                        $combined = $head . ' ' . $tail;
                        $sigs = self::check_content_signatures( $combined );

                        $is_known_security = (
                            false !== strpos( $full_path, 'aios' . DIRECTORY_SEPARATOR . 'firewall-rules' ) ||
                            false !== strpos( $full_path, 'aios/firewall-rules' ) ||
                            false !== strpos( $full_path, 'wflogs' )
                        );

                        if ( $is_known_security && empty( $sigs ) ) {
                            continue;
                        }

                        $size_str = function_exists( 'size_format' ) ? size_format( $size ) : ( round( $size / 1024, 2 ) . ' KB' );

                        if ( $is_known_security && ! empty( $sigs ) ) {
                            $results['infected_files'][] = [
                                'path'               => $full_path,
                                'relative'           => $rel,
                                'size'               => $size_str,
                                'signatures'         => 'کد بدافزار الحاق‌شده به فایل AIOS | ' . implode( ' | ', $sigs ),
                                'is_injected_top'    => false,
                                'is_injected_bottom' => true,
                                'is_writable'        => is_writable( $full_path ),
                                'severity'           => 'critical',
                            ];
                            $results['stats']['threats_count']++;
                            continue;
                        }

                        $results['uploads_php'][] = [
                            'path'          => $full_path,
                            'relative'      => $rel,
                            'size'          => $size_str,
                            'has_assetflow' => ! empty( $sigs ),
                            'is_writable'   => is_writable( $full_path ),
                            'severity'      => 'critical',
                        ];
                        $results['stats']['threats_count']++;
                    }
                }
            } catch ( Exception $e ) {
                // عبور در صورت خطا در دسترسی
            }
        }

        private static function scan_root_files( $root_dir, &$results ) {
            $php_files = glob( $root_dir . '*.php' );
            if ( ! empty( $php_files ) ) {
                foreach ( $php_files as $f ) {
                    if ( is_file( $f ) ) {
                        $results['stats']['total_files_scanned']++;
                        self::inspect_single_php_file( $f, $results );
                    }
                }
            }

            // بررسی فایل wp-config.php در صورتی که یک پوشه بالاتر از ریشه باشد
            $parent_config = dirname( $root_dir ) . '/wp-config.php';
            if ( file_exists( $parent_config ) && ( empty( $php_files ) || ! in_array( $parent_config, $php_files, true ) ) ) {
                $results['stats']['total_files_scanned']++;
                self::inspect_single_php_file( $parent_config, $results );
            }
        }
    }

    if ( ! class_exists( 'AFC_Scanner' ) ) {
        class_alias( 'HO_Anti_Scanner', 'AFC_Scanner' );
    }
}
