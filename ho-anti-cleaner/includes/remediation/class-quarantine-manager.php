<?php
/**
 * Quarantine and Rollback Manager for Gravity Security & HO Anti Cleaner
 * سامانه مدیریت قرنطینه امن، مانیفست متادیتا و بازگردانی خودکار (Rollback)
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Quarantine_Manager' ) ) {

    class HO_Anti_Quarantine_Manager {

        private static function get_quarantine_dir() {
            $upload_dir = wp_upload_dir();
            $dir = $upload_dir['basedir'] . '/afc-quarantine-backups';

            if ( ! file_exists( $dir ) ) {
                wp_mkdir_p( $dir );
            }

            // تضمین حفاظت کامل در برابر اجرای مستقیم یا دانلود عمومی در انواع وب‌سرورها
            self::enforce_directory_protection( $dir );

            return $dir;
        }

        /**
         * مسدودسازی دسترسی وب به پوشه قرنطینه در وب‌سرورهای Apache, Nginx, IIS و LiteSpeed
         */
        public static function enforce_directory_protection( $dir ) {
            // ۱. حفاظت Apache / LiteSpeed
            $htaccess_file = $dir . '/.htaccess';
            if ( ! file_exists( $htaccess_file ) ) {
                $rules = "# Gravity / HO Anti: Deny all direct web access\n"
                       . "<IfModule authz_core_module>\n"
                       . "    Require all denied\n"
                       . "</IfModule>\n"
                       . "<IfModule !authz_core_module>\n"
                       . "    Order Deny,Allow\n"
                       . "    Deny from all\n"
                       . "</IfModule>\n"
                       . "Options -Indexes -ExecCGI\n"
                       . "<FilesMatch \".*\">\n"
                       . "    Order Deny,Allow\n"
                       . "    Deny from all\n"
                       . "</FilesMatch>\n";
                @file_put_contents( $htaccess_file, $rules );
                @chmod( $htaccess_file, 0444 );
            }

            // ۲. فایل شاخص خاموش
            $index_file = $dir . '/index.php';
            if ( ! file_exists( $index_file ) ) {
                @file_put_contents( $index_file, '<?php // Silence is golden' );
                @chmod( $index_file, 0444 );
            }

            // ۳. حفاظت IIS
            $web_config = $dir . '/web.config';
            if ( ! file_exists( $web_config ) ) {
                $iis_rules = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                           . "<configuration>\n"
                           . "    <system.webServer>\n"
                           . "        <authorization>\n"
                           . "            <deny users=\"*\" />\n"
                           . "        </authorization>\n"
                           . "    </system.webServer>\n"
                           . "</configuration>";
                @file_put_contents( $web_config, $iis_rules );
            }
        }

        private static function get_manifest_path() {
            return self::get_quarantine_dir() . '/quarantine_manifest.json';
        }

        public static function get_manifest() {
            $manifest_file = self::get_manifest_path();
            if ( ! file_exists( $manifest_file ) ) {
                return [];
            }

            $content = @file_get_contents( $manifest_file );
            if ( empty( $content ) ) {
                return [];
            }

            $data = json_decode( $content, true );
            return is_array( $data ) ? $data : [];
        }

        private static function save_manifest( array $manifest ) {
            $manifest_file = self::get_manifest_path();
            return false !== @file_put_contents( $manifest_file, json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
        }

        /**
         * انتقال امن فایل به قرنطینه به همراه ثبت در مانیفست
         *
         * @param string $file_path مسیر کامل فایل هدف
         * @param string $reason دلیل انتقال یا یافته مرتبط
         * @param string $operation_type نوع عملیات (before_surgical_repair, before_core_restore, quarantine_only, etc.)
         * @param string $finding_id شناسه یافته در صورت وجود
         * @param bool $remove_source آیا فایل اصلی از مبدأ پاک شود؟ (در قرنطینه ایزوله بله، در پشتیبان قبل جراحی خیر)
         * @return array
         */
        public static function quarantine_file( $file_path, $reason = '', $operation_type = 'quarantine_only', $finding_id = '', $remove_source = false ) {
            if ( function_exists( 'wp_normalize_path' ) ) {
                $file_path = wp_normalize_path( $file_path );
            }

            if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
                return [
                    'success' => false,
                    'message' => 'فایل مبدأ جهت انتقال به قرنطینه یافت نشد یا قابل خواندن نیست: ' . esc_html( $file_path ),
                ];
            }

            $raw_content = @file_get_contents( $file_path );
            if ( false === $raw_content ) {
                return [
                    'success' => false,
                    'message' => 'خطا در خواندن محتوای فایل مبدأ جهت پشتیبان‌گیری.',
                ];
            }

            $file_hash_sha256 = hash( 'sha256', $raw_content );
            $file_hash_md5    = md5( $raw_content );
            $file_size        = filesize( $file_path );

            $backup_id   = 'qbak_' . date( 'Ymd_His' ) . '_' . substr( $file_hash_md5, 0, 8 );
            $safe_name   = sanitize_file_name( basename( $file_path ) ) . '.' . $backup_id . '.quarantine';
            $target_dir  = self::get_quarantine_dir();
            $target_file = $target_dir . '/' . $safe_name;

            // بسته‌بندی امن: کدگذاری محتوا جهت جلوگیری قطعی از قابلیت تفسیر توسط هر مفسری
            $payload = [
                'meta' => [
                    'backup_id'        => $backup_id,
                    'original_path'    => $file_path,
                    'original_size'    => $file_size,
                    'sha256'           => $file_hash_sha256,
                    'md5'              => $file_hash_md5,
                    'timestamp'        => current_time( 'mysql' ),
                    'reason'           => $reason,
                    'operation_type'   => $operation_type,
                    'finding_id'       => $finding_id,
                ],
                // ذخیره محتوا به صورت رمزگذاری Base64 بدون ساختار PHP قابل اجرا
                'content' => base64_encode( $raw_content ),
            ];

            if ( false === @file_put_contents( $target_file, json_encode( $payload ) ) ) {
                return [
                    'success' => false,
                    'message' => 'خطا در ذخیره فایل در دایرکتوری قرنطینه امن.',
                ];
            }

            @chmod( $target_file, 0444 );

            // ثبت در مانیفست متادیتا
            $manifest = self::get_manifest();
            $manifest[ $backup_id ] = [
                'backup_id'            => $backup_id,
                'original_path'        => $file_path,
                'quarantined_filename' => $safe_name,
                'file_size'            => $file_size,
                'file_hash_sha256'     => $file_hash_sha256,
                'file_hash_md5'        => $file_hash_md5,
                'timestamp'            => current_time( 'mysql' ),
                'reason'               => $reason,
                'operation_type'       => $operation_type,
                'finding_id'           => $finding_id,
                'is_restored'          => false,
                'restored_at'          => null,
            ];
            self::save_manifest( $manifest );

            // در صورت درخواست حذف از مبدأ (مانند قرنطینه وب‌شل مستقل)
            if ( $remove_source ) {
                if ( ! is_writable( $file_path ) ) {
                    @chmod( $file_path, 0644 );
                }
                @unlink( $file_path );
            }

            return [
                'success'   => true,
                'backup_id' => $backup_id,
                'path'      => $target_file,
                'hash'      => $file_hash_sha256,
                'message'   => 'فایل با موفقیت با شناسه ' . $backup_id . ' در قرنطینه امن ثبت شد.',
            ];
        }

        /**
         * بازگردانی امن فایل از قرنطینه (Rollback)
         *
         * @param string $backup_id شناسه پشتیبان
         * @return array
         */
        public static function rollback( $backup_id ) {
            $manifest = self::get_manifest();
            if ( ! isset( $manifest[ $backup_id ] ) ) {
                return [
                    'success' => false,
                    'message' => 'شناسه پشتیبان در مانیفست قرنطینه یافت نشد: ' . esc_html( $backup_id ),
                ];
            }

            $entry       = $manifest[ $backup_id ];
            $target_file = self::get_quarantine_dir() . '/' . $entry['quarantined_filename'];

            if ( ! file_exists( $target_file ) || ! is_readable( $target_file ) ) {
                return [
                    'success' => false,
                    'message' => 'فایل بسته قرنطینه در دیسک یافت نشد.',
                ];
            }

            $package_raw = @file_get_contents( $target_file );
            $package     = json_decode( $package_raw, true );

            if ( empty( $package ) || ! isset( $package['content'] ) ) {
                return [
                    'success' => false,
                    'message' => 'فرمت بسته قرنطینه نامعتبر است.',
                ];
            }

            $restored_content = base64_decode( $package['content'] );
            $original_path    = $entry['original_path'];

            // اعتبارسنجی یکپارچگی قبل از بازگردانی
            $current_hash = hash( 'sha256', $restored_content );
            if ( $current_hash !== $entry['file_hash_sha256'] ) {
                return [
                    'success' => false,
                    'message' => 'هش بسته قرنطینه با متادیتای مانیفست مغایرت دارد (احتمال دستکاری بسته). بازگردانی متوقف شد.',
                ];
            }

            // جلوگیری از آسیب Path Traversal
            if ( 0 !== strpos( wp_normalize_path( $original_path ), wp_normalize_path( ABSPATH ) ) ) {
                // اگر خارج از ABSPATH باشد (مثلاً wp-config در یک سطح بالاتر)
                $parent_root = wp_normalize_path( dirname( ABSPATH ) );
                if ( 0 !== strpos( wp_normalize_path( $original_path ), $parent_root ) ) {
                    return [
                        'success' => false,
                        'message' => 'مسیر بازگردانی خارج از ریشه مجاز وردپرس است.',
                    ];
                }
            }

            // اطمینان از وجود دایرکتوری والد
            $parent_dir = dirname( $original_path );
            if ( ! file_exists( $parent_dir ) ) {
                wp_mkdir_p( $parent_dir );
            }

            // اگر فایل در مسیر مقصد وجود دارد و قفل است
            if ( file_exists( $original_path ) && ! is_writable( $original_path ) ) {
                @chmod( $original_path, 0644 );
            }

            // نوشتن محتوای بازیابی‌شده
            if ( false === @file_put_contents( $original_path, $restored_content ) ) {
                return [
                    'success' => false,
                    'message' => 'خطا در نوشتن محتوای بازگردانی‌شده در مسیر اصلی: ' . esc_html( $original_path ),
                ];
            }

            // به‌روزرسانی مانیفست
            $manifest[ $backup_id ]['is_restored'] = true;
            $manifest[ $backup_id ]['restored_at'] = current_time( 'mysql' );
            self::save_manifest( $manifest );

            return [
                'success'       => true,
                'backup_id'     => $backup_id,
                'original_path' => $original_path,
                'message'       => 'فایل با موفقیت بازگردانی (Rollback) شد.',
            ];
        }

        /**
         * دریافت آمار و لیست موارد قرنطینه‌شده
         */
        public static function get_quarantine_stats() {
            $manifest = self::get_manifest();
            $total    = count( $manifest );
            $active   = 0;
            $restored = 0;

            foreach ( $manifest as $item ) {
                if ( ! empty( $item['is_restored'] ) ) {
                    $restored++;
                } else {
                    $active++;
                }
            }

            return [
                'total'    => $total,
                'active'   => $active,
                'restored' => $restored,
                'items'    => array_values( array_reverse( $manifest ) ),
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Quarantine_Manager' ) ) {
        class_alias( 'HO_Anti_Quarantine_Manager', 'Gravity_Quarantine_Manager' );
    }
}
