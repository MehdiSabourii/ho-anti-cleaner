<?php
/**
 * Remediation and Disinfection Engine for HO Anti Cleaner
 * موتور پاک‌سازی، جراحی فایل‌ها و حذف درپشتی‌های دیتابیس
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Cleaner' ) ) {

    class HO_Anti_Cleaner {

        public static function get_backup_dir() {
            $upload_dir = wp_upload_dir();
            $backup_dir = $upload_dir['basedir'] . '/afc-quarantine-backups';
            if ( ! file_exists( $backup_dir ) ) {
                wp_mkdir_p( $backup_dir );
                @file_put_contents( $backup_dir . '/.htaccess', "Order Deny,Allow\nDeny from all\n" );
                @file_put_contents( $backup_dir . '/index.php', '<?php // Silence is golden' );
            }
            return $backup_dir;
        }

        public static function backup_file_external( $source_path ) {
            return self::backup_file( $source_path );
        }

        public static function backup_file( $source_path ) {
            $backup_dir = self::get_backup_dir();
            $safe_name = sanitize_file_name( basename( $source_path ) ) . '_' . date( 'Ymd_His' ) . '.bak';
            return @copy( $source_path, $backup_dir . '/' . $safe_name );
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
                                         ( false !== strpos( $content, 'yrxc_u' ) ) ||
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

                        // استثنا برای index.php استاندارد پوشه‌ها
                        if ( 'index.php' === strtolower( $file->getFilename() ) && $file->getSize() < 120 ) {
                            $check = trim( (string) @file_get_contents( $path ) );
                            if ( empty( $check ) || false !== stripos( $check, 'Silence is golden' ) ) {
                                continue;
                            }
                        }

                        // استثنا برای پوشه‌های مجاز افزونه‌های امنیتی معتبر
                        $is_known_security = (
                            false !== strpos( $path, 'aios' . DIRECTORY_SEPARATOR . 'firewall-rules' ) ||
                            false !== strpos( $path, 'aios/firewall-rules' ) ||
                            false !== strpos( $path, 'wflogs' )
                        );

                        $content = @file_get_contents( $path );
                        $has_signatures = false;
                        if ( class_exists( 'HO_Anti_Scanner' ) ) {
                            $matched_sigs = HO_Anti_Scanner::check_content_signatures( $content );
                            $has_signatures = ! empty( $matched_sigs );
                        }

                        if ( $is_known_security && ! $has_signatures ) {
                            continue;
                        }

                        // به جای حذف کورکورانه، فایل ابتدا به صورت امن قرنطینه و در مانیفست ثبت می‌شود
                        if ( class_exists( 'HO_Anti_Quarantine_Manager' ) ) {
                            $res = HO_Anti_Quarantine_Manager::quarantine_file(
                                $path,
                                'فایل PHP مشکوک و فاقد مجوز در پوشه Uploads',
                                'quarantine_uploads_php',
                                '',
                                true // انتقال به قرنطینه و پاک‌سازی ایمن از مبدأ
                            );

                            if ( $res['success'] ) {
                                $log[] = "فایل PHP در آپلودها به قرنطینه امن منتقل شد (شناسه پشتیبان: " . $res['backup_id'] . "): " . esc_html( basename( $path ) );
                            } else {
                                $log[] = "خطا در انتقال فایل به قرنطینه: " . esc_html( basename( $path ) );
                            }
                        } else {
                            self::backup_file( $path );
                            @unlink( $path );
                            $log[] = "فایل PHP در آپلودها پشتیبان‌گیری و پاک شد: " . esc_html( basename( $path ) );
                        }
                    }
                }
            } catch ( Exception $e ) {
                $log[] = "خطا در اسکن پوشه آپلودها: " . $e->getMessage();
            }

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'هیچ فایل PHP مشکوکی در آپلودها یافت نشد.' ] : $log,
            ];
        }

        /**
         * جراحی و ترمیم هوشمند یک فایل با اعتبارسنجی نحوی قبل و بعد از اصلاح
         */
        public static function repair_single_file( $file_path ) {
            if ( class_exists( 'HO_Anti_Safe_Repair' ) ) {
                return HO_Anti_Safe_Repair::targeted_surgical_repair( $file_path );
            }

            return [ 'success' => false, 'message' => 'موتور جراحی امن در دسترس نیست.' ];
        }

        /**
         * بازگردانی فایل هسته با نسخه رسمی WordPress.org
         */
        public static function restore_core_file( $file_path ) {
            if ( class_exists( 'HO_Anti_Safe_Repair' ) ) {
                return HO_Anti_Safe_Repair::restore_core_file_from_official( $file_path );
            }

            return [ 'success' => false, 'message' => 'موتور بازگردانی رسمی در دسترس نیست.' ];
        }

        /**
         * بازگردانی فایل از قرنطینه (Rollback)
         */
        public static function rollback_quarantine_item( $backup_id ) {
            if ( class_exists( 'HO_Anti_Quarantine_Manager' ) ) {
                return HO_Anti_Quarantine_Manager::rollback( $backup_id );
            }

            return [ 'success' => false, 'message' => 'مدیریت قرنطینه در دسترس نیست.' ];
        }
    }

    if ( ! class_exists( 'AFC_Cleaner' ) ) {
        class_alias( 'HO_Anti_Cleaner', 'AFC_Cleaner' );
    }
}
