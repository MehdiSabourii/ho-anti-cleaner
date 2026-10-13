<?php
/**
 * Remediation and Disinfection Engine for HO Anti Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Cleaner' ) ) {

    class HO_Anti_Cleaner {

        private static function get_backup_dir() {
            $upload_dir = wp_upload_dir();
            $backup_dir = $upload_dir['basedir'] . '/afc-quarantine-backups';
            if ( ! file_exists( $backup_dir ) ) {
                wp_mkdir_p( $backup_dir );
                @file_put_contents( $backup_dir . '/.htaccess', 'Deny from all' );
                @file_put_contents( $backup_dir . '/index.php', '<?php // Silence is golden' );
            }
            return $backup_dir;
        }

        public static function clean_database_artifacts() {
            global $wpdb;

            $log = [];

            // ۱. حذف کاربران مخفی سیستمی و متادیتاها
            $users = $wpdb->get_results( "SELECT ID, user_login FROM {$wpdb->users} WHERE user_login LIKE 'sys_%'" );
            $deleted_users_count = 0;
            if ( ! empty( $users ) ) {
                foreach ( $users as $u ) {
                    $wpdb->delete( $wpdb->users, [ 'ID' => $u->ID ] );
                    $wpdb->delete( $wpdb->usermeta, [ 'user_id' => $u->ID ] );
                    $deleted_users_count++;
                }
            }
            if ( $deleted_users_count > 0 ) {
                $log[] = "تعداد $deleted_users_count کاربر مخفی (sys_*) از دیتابیس پاک شدند.";
            }

            // ۲. حذف آپشن‌های مخرب
            $options_to_remove = [ 'jsonmetafield', 'sub_valid_adm', 'sub_valid_adm1' ];
            $placeholders = implode( "','", array_map( 'esc_sql', $options_to_remove ) );
            $deleted_options = $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name IN ('$placeholders')" );
            if ( $deleted_options ) {
                $log[] = "کلیدهای مخرب (jsonmetafield و sub_valid_adm*) از جدول wp_options حذف شدند.";
            }

            // ۳. حذف جداول اختصاصی بدافزار (wp_sys_av_*)
            $db_prefix = $wpdb->prefix;
            $tables = $wpdb->get_col( "SHOW TABLES LIKE '{$db_prefix}sys_av_%'" );
            if ( ! empty( $tables ) ) {
                foreach ( $tables as $tbl ) {
                    $wpdb->query( "DROP TABLE IF EXISTS `$tbl`" );
                    $log[] = "جدول ردگیری بدافزار `$tbl` حذف گردید.";
                }
            }

            wp_cache_flush();

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'دیتابیس از قبل پاک بود.' ] : $log,
            ];
        }

        public static function clean_mu_plugins() {
            $mu_dirs = array_unique( [
                defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
                WP_CONTENT_DIR . '/mu-plugins',
            ] );
            $log = [];

            foreach ( $mu_dirs as $mu_dir ) {
                if ( ! is_dir( $mu_dir ) ) continue;

                try {
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator( $mu_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                    );

                    foreach ( $iterator as $file ) {
                        if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                            $full_path = $file->getRealPath();
                            $filename  = $file->getFilename();
                            $content   = @file_get_contents( $full_path, false, null, 0, 2097152 );

                            $is_target = ( false !== strpos( $filename, '01-mu-' ) ) ||
                                         ( false !== stripos( $filename, 'asset-flow' ) ) ||
                                         ( false !== stripos( $content, 'Asset Flow' ) ) ||
                                         ( false !== strpos( $content, 'WP_Sys_Optimiser' ) ) ||
                                         ( false !== strpos( $content, 'xCzpFLgFPHRLRAiM' ) ) ||
                                         ( false !== strpos( $content, 'AV_COMPLETED' ) );

                            if ( $is_target ) {
                                self::backup_file( $full_path );
                                if ( @unlink( $full_path ) ) {
                                    $log[] = "فایل درپشتی mu-plugin حذف شد: " . esc_html( $filename );
                                } else {
                                    $log[] = "خطا در حذف فایل mu-plugin: " . esc_html( $filename ) . " (دسترسی دایرکتوری را بررسی کنید)";
                                }
                            }
                        }
                    }
                } catch ( Exception $e ) {
                    // در صورت بروز خطا
                }
            }

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'فایل آلوده‌ای در mu-plugins یافت نشد.' ] : $log,
            ];
        }

        public static function clean_uploads_php() {
            $upload_dir = wp_upload_dir();
            $target_dir = $upload_dir['basedir'];
            $log = [];

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $target_dir, RecursiveDirectoryIterator::SKIP_DOTS )
                );

                foreach ( $iterator as $file ) {
                    if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                        $path = $file->getRealPath();
                        if ( false !== strpos( $path, 'afc-quarantine-backups' ) ) {
                            continue;
                        }
                        self::backup_file( $path );
                        if ( @unlink( $path ) ) {
                            $log[] = "فایل PHP مشکوک در آپلودها حذف شد: " . esc_html( basename( $path ) );
                        }
                    }
                }
            } catch ( Exception $e ) {
                $log[] = "خطا در اسکن پوشه آپلودها: " . $e->getMessage();
            }

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'هیچ فایل PHP در آپلودها یافت نشد.' ] : $log,
            ];
        }

        public static function repair_single_file( $file_path ) {
            if ( function_exists( 'wp_normalize_path' ) ) {
                $file_path = wp_normalize_path( $file_path );
            }
            if ( ! file_exists( $file_path ) && file_exists( ABSPATH . ltrim( $file_path, '/' ) ) ) {
                $file_path = ABSPATH . ltrim( $file_path, '/' );
            }

            if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
                return [ 'success' => false, 'message' => 'فایل در مسیر مشخص شده یافت نشد.' ];
            }

            // اگر فایل بخشی از خود افزونه یا نسخه قبلی پاک‌ساز است، نیاز به ترمیم ندارد
            if ( false !== strpos( $file_path, 'wp-assetflow-cleaner' ) || false !== strpos( $file_path, 'ho-anti-cleaner' ) ) {
                // اگر نسخه قبلی در پوشه نامعتبر است، حذف آن به عنوان فایل زائد
                @unlink( $file_path );
                return [
                    'success' => true,
                    'action'  => 'deleted',
                    'message' => 'فایل زائد نسخه قبلی پاک‌ساز با موفقیت حذف شد.',
                ];
            }

            if ( ! is_writable( $file_path ) ) {
                return [ 'success' => false, 'message' => 'فایل قابل ویرایش نیست (سطح دسترسی را به 0644 تغییر دهید).' ];
            }

            $content = @file_get_contents( $file_path );
            if ( false === $content ) {
                return [ 'success' => false, 'message' => 'امکان خواندن محتوای فایل وجود ندارد.' ];
            }

            // تقسیم رشته‌ها برای جلوگیری از شناسایی اشتباه کد همین افزونه توسط اسکنرها
            $markers = [
                '/* Plugin Name:' . ' Asset Flow',
                'Plugin Name:' . ' Asset Flow',
                'goto ' . 'xCzpFLgF' . 'PHRLRAiM;',
                'class ' . 'WP_Sys_' . 'Optimiser',
                'AV_' . 'COMPLETED',
            ];

            $earliest_pos = false;
            foreach ( $markers as $marker ) {
                $pos = strpos( $content, $marker );
                if ( false !== $pos ) {
                    if ( false === $earliest_pos || $pos < $earliest_pos ) {
                        $earliest_pos = $pos;
                    }
                }
            }

            if ( false === $earliest_pos ) {
                return [ 'success' => false, 'message' => 'کد تزریقی Asset Flow در این فایل پیدا نشد.' ];
            }

            self::backup_file( $file_path );

            if ( $earliest_pos < 300 && false !== strpos( $content, 'Plugin Name: Asset Flow' ) ) {
                if ( @unlink( $file_path ) ) {
                    return [
                        'success' => true,
                        'action'  => 'deleted',
                        'message' => 'فایل اختصاصی بدافزار شناسایی و به طور کامل حذف شد.',
                    ];
                }
            }

            $clean_code = substr( $content, 0, $earliest_pos );
            $clean_code = preg_replace( '/\?>\s*<\?php\s*$/', '', $clean_code );
            $clean_code = preg_replace( '/\?>\s*$/', '', $clean_code );
            $clean_code = rtrim( $clean_code ) . "\n";

            if ( false !== @file_put_contents( $file_path, $clean_code ) ) {
                return [
                    'success' => true,
                    'action'  => 'repaired',
                    'message' => 'کد مخرب تزریق‌شده با موفقیت از انتهای فایل پاک و فایل ترمیم شد.',
                ];
            }

            return [ 'success' => false, 'message' => 'خطا در بازنویسی و ذخیره فایل.' ];
        }

        private static function backup_file( $source_path ) {
            $backup_dir = self::get_backup_dir();
            $safe_name = sanitize_file_name( basename( $source_path ) ) . '_' . date( 'Ymd_His' ) . '.bak';
            @copy( $source_path, $backup_dir . '/' . $safe_name );
        }
    }

    if ( ! class_exists( 'AFC_Cleaner' ) ) {
        class_alias( 'HO_Anti_Cleaner', 'AFC_Cleaner' );
    }
}
