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

            // ۴. پاک‌سازی تزریق‌های اسکریپت در محتوای پست‌ها و قالب المنتور (EtherHiding / Web3 C2)
            $script_res = self::clean_database_script_injections();
            if ( ! empty( $script_res['log'] ) ) {
                $log = array_merge( $log, $script_res['log'] );
            }

            // ۵. اصلاح آدرس اصلی سایت در صورت دستکاری (Site URL / Home Tampering)
            $siteurl_res = self::restore_tampered_siteurl();
            if ( ! empty( $siteurl_res['log'] ) && false === strpos( $siteurl_res['log'][0], 'معتبر است' ) ) {
                $log = array_merge( $log, $siteurl_res['log'] );
            }

            wp_cache_flush();

            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'database_cleaned',
                    "عملیات پاک‌سازی کامل دیتابیس اجرا شد (" . count( $log ) . " اقدام ثبت گردید).",
                    [ 'actions' => $log ]
                );
            }

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'دیتابیس از قبل پاک بود.' ] : $log,
            ];
        }

        /**
         * پاک‌سازی جراحی کدهای تزریقی EtherHiding، Web3 C2 و ریدایرکت‌های مخرب از جداول wp_posts و المنتور
         */
        public static function clean_database_script_injections() {
            global $wpdb;
            $log = [];

            if ( empty( $wpdb ) ) {
                return [ 'success' => false, 'log' => [ 'دسترسی به پایگاه داده موجود نیست.' ] ];
            }

            $malware_terms = [
                'polygon-bor-rpc',
                '1rpc.io',
                '0xb29927B7D854b232D5E58CFc201866376E68C676',
                '0x2cae8ae4',
                'eth_call',
                'data-no-optimize="1"',
            ];

            $like_clauses = [];
            foreach ( $malware_terms as $term ) {
                $like_clauses[] = $wpdb->prepare( "post_content LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $where_sql = implode( ' OR ', $like_clauses );

            $patterns = [
                '/<script[^>]*>(?:(?!<\/script>).)*(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call)(?:(?!<\/script>).)*<\/script>/is',
                '/<script[^>]*data-no-optimize=[\'"]1[\'"][^>]*>(?:(?!<\/script>).)*(?:wp-settings|wpadminbar)(?:(?!<\/script>).)*(?:XMLHttpRequest|createElement\([\'"]script[\'"]\))(?:(?!<\/script>).)*<\/script>/is',
            ];

            // ۱. پاک‌سازی جدول wp_posts
            $posts = $wpdb->get_results( "SELECT ID, post_content FROM {$wpdb->posts} WHERE {$where_sql}" );
            $cleaned_count = 0;
            if ( ! empty( $posts ) ) {
                foreach ( $posts as $p ) {
                    $original = $p->post_content;
                    $cleaned  = $original;
                    foreach ( $patterns as $pat ) {
                        $cleaned = preg_replace( $pat, '', $cleaned );
                    }

                    if ( $cleaned !== $original ) {
                        $wpdb->update(
                            $wpdb->posts,
                            [ 'post_content' => $cleaned ],
                            [ 'ID' => $p->ID ],
                            [ '%s' ],
                            [ '%d' ]
                        );
                        $cleaned_count++;
                    }
                }
            }
            if ( $cleaned_count > 0 ) {
                $log[] = "تعداد $cleaned_count پست/برگه آلوده به اسکریپت‌های EtherHiding و Web3 پاک‌سازی شدند.";
            }

            // ۲. پاک‌سازی جدول wp_postmeta (به خصوص المنتور)
            $meta_like = [];
            foreach ( $malware_terms as $term ) {
                $meta_like[] = $wpdb->prepare( "meta_value LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $meta_where = implode( ' OR ', $meta_like );
            $metas = $wpdb->get_results( "SELECT meta_id, meta_value FROM {$wpdb->postmeta} WHERE {$meta_where}" );
            $meta_cleaned = 0;
            if ( ! empty( $metas ) ) {
                foreach ( $metas as $m ) {
                    $orig_m = $m->meta_value;
                    $clean_m = $orig_m;
                    foreach ( $patterns as $pat ) {
                        $clean_m = preg_replace( $pat, '', $clean_m );
                    }
                    if ( $clean_m !== $orig_m ) {
                        $wpdb->update(
                            $wpdb->postmeta,
                            [ 'meta_value' => $clean_m ],
                            [ 'meta_id' => $m->meta_id ],
                            [ '%s' ],
                            [ '%d' ]
                        );
                        $meta_cleaned++;
                    }
                }
            }
            if ( $meta_cleaned > 0 ) {
                $log[] = "تعداد $meta_cleaned رکورد متادیتای المنتور/پست آلوده به اسکریپت Web3 پاک‌سازی گردید.";
            }

            // ۳. پاک‌سازی جدول wp_options (ویجت‌های HTML، تنظیمات هدر/فوتر)
            $opt_like = [];
            foreach ( $malware_terms as $term ) {
                $opt_like[] = $wpdb->prepare( "option_value LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' );
            }
            $opt_where = implode( ' OR ', $opt_like );
            $options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE {$opt_where}" );
            $opt_cleaned = 0;
            if ( ! empty( $options ) ) {
                foreach ( $options as $o ) {
                    $orig_o = $o->option_value;
                    $clean_o = $orig_o;
                    foreach ( $patterns as $pat ) {
                        $clean_o = preg_replace( $pat, '', $clean_o );
                    }
                    if ( $clean_o !== $orig_o ) {
                        update_option( $o->option_name, $clean_o );
                        $opt_cleaned++;
                    }
                }
            }
            if ( $opt_cleaned > 0 ) {
                $log[] = "تعداد $opt_cleaned آپشن دیتابیس حاوی اسکریپت تزریقی پاک‌سازی شد.";
            }

            // ۴. بررسی و جراحی فایل‌های پوسته فعال (header.php, footer.php, functions.php)
            if ( function_exists( 'get_stylesheet_directory' ) ) {
                $theme_dir = get_stylesheet_directory();
                if ( is_dir( $theme_dir ) ) {
                    $theme_files = [ 'header.php', 'footer.php', 'index.php', 'functions.php' ];
                    foreach ( $theme_files as $tf ) {
                        $tf_path = $theme_dir . '/' . $tf;
                        if ( file_exists( $tf_path ) && is_readable( $tf_path ) ) {
                            $tf_content = @file_get_contents( $tf_path );
                            if ( ! empty( $tf_content ) && preg_match( '/(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4)/i', $tf_content ) ) {
                                self::backup_file_external( $tf_path );
                                $tf_cleaned = $tf_content;
                                foreach ( $patterns as $pat ) {
                                    $tf_cleaned = preg_replace( $pat, '', $tf_cleaned );
                                }
                                if ( $tf_cleaned !== $tf_content && is_writable( $tf_path ) ) {
                                    @file_put_contents( $tf_path, $tf_cleaned );
                                    $log[] = "اسکریپت تزریقی از فایل پوسته ($tf) با موفقیت جراحی و حذف شد.";
                                }
                            }
                        }
                    }
                }
            }

            // ۵. پاک‌سازی کش افزونه‌های بهینه‌ساز و قالب‌ساز (Autoptimize و Elementor و کش فیزیکی دیسک)
            if ( class_exists( 'autoptimizeCache' ) && method_exists( 'autoptimizeCache', 'clearall' ) ) {
                autoptimizeCache::clearall();
                $log[] = "حافظه کش Autoptimize جهت حذف کامل اسکریپت‌های ترکیب‌شده تخلیه شد.";
            }

            // تخلیه دستی فایل‌های کش Autoptimize از روی دیسک
            $autoptimize_cache_dir = ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content' ) . '/cache/autoptimize';
            if ( is_dir( $autoptimize_cache_dir ) ) {
                self::purge_cache_directory( $autoptimize_cache_dir );
                $log[] = "فایل‌های کش استاتیک Autoptimize از پوشه wp-content/cache/autoptimize حذف شدند.";
            }

            if ( class_exists( '\Elementor\Plugin' ) && isset( \Elementor\Plugin::$instance->files_manager ) ) {
                \Elementor\Plugin::$instance->files_manager->clear_cache();
                $log[] = "حافظه کَش CSS و فایل‌های المنتور تخلیه گردید.";
            }

            if ( function_exists( 'wp_cache_flush' ) ) {
                wp_cache_flush();
            }

            return [
                'success'       => true,
                'cleaned_count' => $cleaned_count,
                'log'           => $log,
            ];
        }

        /**
         * اصلاح و بازگردانی آدرس‌های اصلی سایت (siteurl و home) در صورت دستکاری دیتابیس توسط مهاجم
         */
        public static function restore_tampered_siteurl( $target_url = '' ) {
            $log = [];

            if ( empty( $target_url ) ) {
                $trusted_siteurl = get_option( 'ho_anti_trusted_siteurl', '' );
                $trusted_home    = get_option( 'ho_anti_trusted_home', '' );

                if ( ! empty( $trusted_siteurl ) ) {
                    $target_url = $trusted_siteurl;
                } else {
                    $proto = ( isset( $_SERVER['HTTPS'] ) && 'on' === $_SERVER['HTTPS'] ) ? 'https://' : 'http://';
                    $host  = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( $_SERVER['HTTP_HOST'] ) : '';
                    if ( ! empty( $host ) ) {
                        $target_url = $proto . $host;
                    }
                }
            }

            if ( empty( $target_url ) ) {
                return [ 'success' => false, 'message' => 'امکان تشخیص آدرس معتبر سایت وجود ندارد.' ];
            }

            $current_siteurl = get_option( 'siteurl', '' );
            $current_home    = get_option( 'home', '' );

            if ( $current_siteurl !== $target_url ) {
                update_option( 'siteurl', $target_url );
                $log[] = "آدرس siteurl از {$current_siteurl} به {$target_url} اصلاح گردید.";
            }

            if ( $current_home !== $target_url ) {
                update_option( 'home', $target_url );
                $log[] = "آدرس home از {$current_home} به {$target_url} اصلاح گردید.";
            }

            update_option( 'ho_anti_trusted_siteurl', $target_url, false );
            update_option( 'ho_anti_trusted_home', $target_url, false );

            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'siteurl_restored',
                    "آدرس اصلی سایت در پایگاه داده بازگردانی شد: $target_url",
                    [ 'restored_url' => $target_url ]
                );
            }

            return [
                'success' => true,
                'log'     => empty( $log ) ? [ 'آدرس سایت معتبر است و تغییری لازم نبود.' ] : $log,
            ];
        }

        /**
         * حذف ایمن یک فایل با انتقال پیشین به قرنطینه و مانیفست جهت امکان بازگردانی (Rollback)
         */
        public static function delete_file_safely( $file_path, $reason = 'حذف فایل مخرب یا غیررسمی' ) {
            $real_path = realpath( $file_path );
            if ( false === $real_path || ! file_exists( $real_path ) ) {
                return [ 'success' => false, 'message' => 'فایل مورد نظر در مسیر مشخص‌شده یافت نشد.' ];
            }

            $abs_path  = defined( 'ABSPATH' ) ? wp_normalize_path( ABSPATH ) : '';
            $norm_path = wp_normalize_path( $real_path );

            if ( ! empty( $abs_path ) && 0 !== strpos( $norm_path, $abs_path ) ) {
                return [ 'success' => false, 'message' => 'حذف فایل‌های خارج از ریشه وردپرس مجاز نیست.' ];
            }

            // فایل‌های حیاتی که تحت هیچ شرایطی نباید حذف شوند
            $protected_files = [
                $abs_path . 'wp-config.php',
                $abs_path . 'index.php',
                $abs_path . 'wp-settings.php',
                $abs_path . 'wp-load.php',
                $abs_path . 'wp-blog-header.php',
            ];
            if ( in_array( $norm_path, $protected_files, true ) ) {
                return [ 'success' => false, 'message' => 'حذف فایل حیاتی ریشه وردپرس مجاز نیست.' ];
            }

            // انتقال فایل به قرنطینه امن همراه با متادیتا و هش SHA256 قبل از حذف
            $backup_id = '';
            if ( class_exists( 'HO_Anti_Quarantine_Manager' ) ) {
                $q_res = HO_Anti_Quarantine_Manager::quarantine_file(
                    $real_path,
                    $reason,
                    'user_requested_delete',
                    '',
                    true // انتقال به قرنطینه و پاک‌سازی ایمن از مبدأ
                );

                if ( $q_res['success'] ) {
                    $backup_id = $q_res['backup_id'];
                } else {
                    return [ 'success' => false, 'message' => 'خطا در پشتیبان‌گیری امن در قرنطینه: ' . $q_res['message'] ];
                }
            } else {
                self::backup_file( $real_path );
                if ( ! @unlink( $real_path ) ) {
                    return [ 'success' => false, 'message' => 'خطا در حذف فیزیکی فایل از روی سرور (دسترسی دایرکتوری را بررسی نمایید).' ];
                }
            }

            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'file_deleted',
                    "فایل با موفقیت حذف و نسخه پشتیبان آن در قرنطینه ذخیره شد: " . basename( $norm_path ),
                    [
                        'path'      => $norm_path,
                        'backup_id' => $backup_id,
                        'reason'    => $reason,
                    ]
                );
            }

            return [
                'success'   => true,
                'backup_id' => $backup_id,
                'message'   => 'فایل با موفقیت به قرنطینه امن منتقل و از روی سرور حذف شد.',
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
         * پاک‌سازی بازگشتی فایل‌های موقت کش در صورت وجود دایرکتوری
         */
        public static function purge_cache_directory( $dir ) {
            if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
                return;
            }
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ( $iterator as $item ) {
                    if ( $item->isDir() ) {
                        @rmdir( $item->getRealPath() );
                    } else {
                        @unlink( $item->getRealPath() );
                    }
                }
            } catch ( Throwable $t ) {
                // نادیده گرفتن خطاهای مجوز در هاست
            }
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
