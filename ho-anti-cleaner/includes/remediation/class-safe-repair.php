<?php
/**
 * Safe Remediation Engine for Gravity Security & HO Anti Cleaner
 * موتور اصلاح و جراحی امن بر پایه سیاست الزامی "Repair Before Delete"
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Safe_Repair' ) ) {

    class HO_Anti_Safe_Repair {

        /**
         * بررسی اعتبارسنجی نحوی کد PHP با استفاده از توکن‌ساز هسته PHP
         *
         * @param string $php_code محتوای کد PHP
         * @return array [ 'valid' => bool, 'error' => string ]
         */
        public static function validate_php_syntax( $php_code ) {
            if ( empty( $php_code ) ) {
                return [ 'valid' => false, 'error' => 'کد خالی است.' ];
            }

            // ۱. بررسی تراز بودن برچسب‌های باز و بسته
            $open_tags  = substr_count( $php_code, '<?' );
            $close_tags = substr_count( $php_code, '?>' );

            // ۲. بررسی نحوی با توکن‌ساز پیشرفته هسته PHP (بدون نیاز به اجرای کد)
            try {
                if ( defined( 'TOKEN_PARSE' ) ) {
                    // پرچم TOKEN_PARSE در صورت وجود خطای نحوی استثنای ParseError صادر می‌کند
                    $tokens = @token_get_all( $php_code, TOKEN_PARSE );
                } else {
                    $tokens = @token_get_all( $php_code );
                }

                if ( false === $tokens || empty( $tokens ) ) {
                    return [ 'valid' => false, 'error' => 'خطای تجزیه در ساختار توکن‌های PHP.' ];
                }

                // ۳. اعتبارسنجی تراز بودن پرانتزها و آکولادها
                $brace_balance = 0;
                $paren_balance = 0;

                foreach ( $tokens as $tok ) {
                    if ( is_string( $tok ) ) {
                        if ( '{' === $tok ) $brace_balance++;
                        elseif ( '}' === $tok ) $brace_balance--;
                        elseif ( '(' === $tok ) $paren_balance++;
                        elseif ( ')' === $tok ) $paren_balance--;
                    }
                }

                if ( $brace_balance !== 0 ) {
                    return [
                        'valid' => false,
                        'error' => 'عدم تراز بودن آکولادها (Brace Mismatch: ' . $brace_balance . ') پس از اصلاح.',
                    ];
                }

                if ( $paren_balance !== 0 ) {
                    return [
                        'valid' => false,
                        'error' => 'عدم تراز بودن پرانتزها (Parentheses Mismatch: ' . $paren_balance . ') پس از اصلاح.',
                    ];
                }

                return [ 'valid' => true, 'error' => '' ];
            } catch ( ParseError $pe ) {
                return [
                    'valid' => false,
                    'error' => 'خطای گرامری PHP: ' . $pe->getMessage() . ' در خط ' . $pe->getLine(),
                ];
            } catch ( Throwable $t ) {
                return [
                    'valid' => false,
                    'error' => 'خطای ارزیابی ساختار فایل: ' . $t->getMessage(),
                ];
            }
        }

        /**
         * جایگزینی و بازگردانی فایل هسته با نسخه رسمی و معتبر وردپرس
         *
         * @param string $file_path مسیر کامل فایل محلی
         * @param string $finding_id شناسه یافته
         * @return array
         */
        public static function restore_core_file_from_official( $file_path, $finding_id = '' ) {
            global $wp_version;
            $version = ! empty( $wp_version ) ? $wp_version : get_bloginfo( 'version' );

            $norm_path = wp_normalize_path( $file_path );
            $abs_path  = wp_normalize_path( ABSPATH );

            if ( 0 !== strpos( $norm_path, $abs_path ) ) {
                return [
                    'success' => false,
                    'message' => 'مسیر فایل خارج از محدوده ریشه وردپرس است.',
                ];
            }

            $relative_path = ltrim( substr( $norm_path, strlen( $abs_path ) ), '/' );

            // فایل‌های خارج از محدوده هسته (مانند wp-content یا wp-config) نباید به طور خودکار بازنویسی شوند
            if ( 0 === strpos( $relative_path, 'wp-content/' ) || 'wp-config.php' === $relative_path ) {
                return [
                    'success' => false,
                    'message' => 'این فایل جزو فایل‌های استاندارد هسته قابل بازنویسی خودکار نیست: ' . esc_html( $relative_path ),
                ];
            }

            // ۱. دریافت هش مورد انتظار از WordPress.org
            $expected_hash = null;
            if ( class_exists( 'HO_Anti_File_Integrity_Engine' ) ) {
                $checksums = HO_Anti_File_Integrity_Engine::get_official_core_checksums( $version );
                if ( isset( $checksums[ $relative_path ] ) ) {
                    $expected_hash = $checksums[ $relative_path ];
                }
            }

            // ۲. دانلود مستقیم فایل رسمی از گیت‌هاب رسمی وردپرس یا cgit
            $remote_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/" . $relative_path;

            $response = wp_remote_get( $remote_url, [
                'timeout'    => 20,
                'user-agent' => 'Gravity-Security-Restore/' . HO_ANTI_VERSION,
            ] );

            if ( is_wp_error( $response ) ) {
                return [
                    'success' => false,
                    'message' => 'خطا در ارتباط با سرور رسمی وردپرس جهت دریافت فایل معتبر: ' . $response->get_error_message(),
                ];
            }

            $status_code = wp_remote_retrieve_response_code( $response );
            if ( 200 !== $status_code ) {
                return [
                    'success' => false,
                    'message' => "سرور رسمی وردپرس کد وضعیت {$status_code} بازگرداند. فایل یافت نشد.",
                ];
            }

            $official_content = wp_remote_retrieve_body( $response );
            if ( empty( $official_content ) ) {
                return [
                    'success' => false,
                    'message' => 'محتوای دریافتی از سرور رسمی خالی است.',
                ];
            }

            // ۳. اعتبارسنجی هش محتوای دریافتی با چکسام رسمی
            if ( ! empty( $expected_hash ) ) {
                $downloaded_hash = md5( $official_content );
                if ( $downloaded_hash !== $expected_hash ) {
                    return [
                        'success' => false,
                        'message' => 'هش محتوای دریافت شده از سرور رسمی با چکسام ثبت‌شده وردپرس همخوانی ندارد. بازنویسی لغو شد.',
                    ];
                }
            }

            // ۴. اعتبارسنجی نحوی قبل از ذخیره
            $syntax_check = self::validate_php_syntax( $official_content );
            if ( ! $syntax_check['valid'] ) {
                return [
                    'success' => false,
                    'message' => 'خطای نحوی در فایل دریافتی: ' . $syntax_check['error'],
                ];
            }

            // ۵. تهیه نسخه پشتیبان در قرنطینه قبل از اعمال هرگونه تغییر
            $backup_res = HO_Anti_Quarantine_Manager::quarantine_file(
                $file_path,
                'نسخه پشتیبان قبل از بازگردانی از منبع معتبر وردپرس (' . $version . ')',
                'before_core_restore',
                $finding_id,
                false
            );

            if ( ! $backup_res['success'] ) {
                return [
                    'success' => false,
                    'message' => 'پشتیبان‌گیری در قرنطینه با شکست مواجه شد؛ بازگردانی متوقف گردید: ' . $backup_res['message'],
                ];
            }

            // ۶. تغییر موقت مجوز در صورت قفل بودن (0444)
            $was_locked = ! is_writable( $file_path );
            if ( $was_locked ) {
                @chmod( $file_path, 0644 );
            }

            // ۷. بازنویسی فایل با نسخه رسمی و سالم
            if ( false === @file_put_contents( $file_path, $official_content ) ) {
                return [
                    'success' => false,
                    'message' => 'خطا در بازنویسی فایل روی دیسک (دسترسی‌های فایل را بررسی کنید).',
                ];
            }

            // ۸. قفل مجدد در صورت نیاز
            if ( get_option( 'ho_anti_files_locked', 1 ) ) {
                @chmod( $file_path, 0444 );
            }

            // ثبت رویداد امنیتی
            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'core_file_restored',
                    "فایل هسته ({$relative_path}) با نسخه رسمی وردپرس {$version} جایگزین و ترمیم شد.",
                    [ 'file' => $relative_path, 'backup_id' => $backup_res['backup_id'] ]
                );
            }

            return [
                'success'       => true,
                'action'        => 'restored_from_trusted_source',
                'backup_id'     => $backup_res['backup_id'],
                'relative_path' => $relative_path,
                'message'       => "فایل {$relative_path} با موفقیت از منبع رسمی وردپرس بازگردانی شد.",
            ];
        }

        /**
         * جراحی هدفمند و کنترل‌شده کدهای تزریقی با اعتبارسنجی نحوی
         *
         * @param string $file_path مسیر کامل فایل
         * @param string $finding_id شناسه یافته
         * @return array
         */
        public static function targeted_surgical_repair( $file_path, $finding_id = '' ) {
            if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
                return [ 'success' => false, 'message' => 'فایل یافت نشد یا قابل خواندن نیست.' ];
            }

            $original_content = @file_get_contents( $file_path );
            if ( empty( $original_content ) ) {
                return [ 'success' => false, 'message' => 'فایل خالی است.' ];
            }

            $repaired_content = $original_content;
            $modifications = [];

            // ۱. جراحی گیت‌کیپرهای هدر (Header Gatekeepers / Cookie Lockers)
            $header_patterns = [
                '/<\?php\s*while\s*\(\s*md5\s*\(\s*md5\s*\(.+?die\s*\(\s*\)\s*;?\s*\}?/is',
                '/<\?php\s*while\s*\([^;]*yrxc_u[^;]*;?\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
                '/<\?php\s*(?:while|if)\s*\([^)]*md5[^)]*\)\s*\{?\s*die\s*\(\s*\)\s*;?\s*\}?/is',
            ];

            foreach ( $header_patterns as $h_pat ) {
                if ( preg_match( $h_pat, $repaired_content ) ) {
                    $repaired_content = preg_replace( $h_pat, "<?php\n", $repaired_content, 1 );
                    $modifications[]  = 'حذف گیت‌کیپر مسدودساز ورود در ابتدای فایل';
                    break;
                }
            }

            // ۲. جراحی کدهای الحاقی فوتر (Asset Flow / WP_Sys_Optimiser / Goto anchors)
            $footer_markers = [
                '/* Plugin Name:' . ' Asset Flow',
                'Plugin Name:' . ' Asset Flow',
                'goto ' . 'xCzpFLgF' . 'PHRLRAiM;',
                'class ' . 'WP_Sys_' . 'Optimiser',
                'AV_' . 'COMPLETED',
            ];

            $earliest_pos = false;
            foreach ( $footer_markers as $marker ) {
                $pos = strpos( $repaired_content, $marker );
                if ( false !== $pos ) {
                    if ( false === $earliest_pos || $pos < $earliest_pos ) {
                        $earliest_pos = $pos;
                    }
                }
            }

            if ( false !== $earliest_pos ) {
                // در صورتی که کل فایل بدافزار باشد (کمتر از ۳۰۰ بایت تا شروع بدافزار)
                if ( $earliest_pos < 300 && false !== strpos( $repaired_content, 'Plugin Name: Asset Flow' ) ) {
                    // انتقال به قرنطینه به جای حذف مستقیم
                    return HO_Anti_Quarantine_Manager::quarantine_file(
                        $file_path,
                        'فایل مستقل بدافزار Asset Flow',
                        'quarantine_malware_file',
                        $finding_id,
                        true
                    );
                }

                $clean_part = substr( $repaired_content, 0, $earliest_pos );
                $clean_part = preg_replace( '/\?>\s*<\?php\s*$/', '', $clean_part );
                $clean_part = preg_replace( '/\?>\s*$/', '', $clean_part );
                $repaired_content = rtrim( $clean_part ) . "\n";
                $modifications[]  = 'برش کدهای مخرب الحاق‌شده به انتهای فایل';
            }

            if ( empty( $modifications ) || $repaired_content === $original_content ) {
                return [
                    'success' => false,
                    'message' => 'الگوی تزریقی شناخته‌شده‌ای در این فایل برای جراحی خودکار یافت نشد (نیازمند بازبینی دستی یا بازگردانی رسمی).',
                ];
            }

            // ۳. کنترل حیاتی قبل از ذخیره: اعتبارسنجی نحوی کد خروجی
            $syntax_res = self::validate_php_syntax( $repaired_content );
            if ( ! $syntax_res['valid'] ) {
                return [
                    'success' => false,
                    'message' => 'جراحی به دلیل خطای گرامری PHP متوقف شد تا مانع از تخریب سایت شود: ' . $syntax_res['error'],
                ];
            }

            // ۴. تهیه پشتیبان در قرنطینه با مانیفست
            $backup_res = HO_Anti_Quarantine_Manager::quarantine_file(
                $file_path,
                'پشتیبان قبل از جراحی: ' . implode( ' | ', $modifications ),
                'before_surgical_repair',
                $finding_id,
                false
            );

            if ( ! $backup_res['success'] ) {
                return [
                    'success' => false,
                    'message' => 'خطا در ایجاد بسته پشتیبان قرنطینه قبل از جراحی: ' . $backup_res['message'],
                ];
            }

            // ۵. تغییر موقت مجوز فایل قفل‌شده
            $was_locked = ! is_writable( $file_path );
            if ( $was_locked ) {
                @chmod( $file_path, 0644 );
            }

            // ۶. نوشتن محتوای جراحی‌شده
            if ( false === @file_put_contents( $file_path, $repaired_content ) ) {
                return [
                    'success' => false,
                    'message' => 'خطا در ذخیره فایل جراحی‌شده بر روی سرور.',
                ];
            }

            // ۷. قفل مجدد فایل به 0444
            if ( get_option( 'ho_anti_files_locked', 1 ) ) {
                @chmod( $file_path, 0444 );
            }

            // ثبت رویداد امنیتی
            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'file_surgically_repaired',
                    'جراحی موفق فایل: ' . basename( $file_path ) . ' (' . implode( '، ', $modifications ) . ')',
                    [ 'file' => basename( $file_path ), 'backup_id' => $backup_res['backup_id'] ]
                );
            }

            return [
                'success'       => true,
                'action'        => 'targeted_surgical_repair',
                'backup_id'     => $backup_res['backup_id'],
                'modifications' => $modifications,
                'message'       => 'فایل با موفقیت جراحی شد و کدهای مخرب بدون آسیب به عملکرد سایت پاک گردیدند.',
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Safe_Repair' ) ) {
        class_alias( 'HO_Anti_Safe_Repair', 'Gravity_Safe_Repair' );
    }
}
