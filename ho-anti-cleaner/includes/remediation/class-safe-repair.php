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
         * تشخیص اینکه آیا یک فایل متعلق به هسته وردپرس است یا خیر
         *
         * @param string $file_path مسیر کامل فایل
         * @return bool
         */
        public static function is_core_file( $file_path ) {
            $abs_path  = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( ABSPATH ) : str_replace( '\\', '/', ABSPATH );
            $norm_path = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $file_path ) : str_replace( '\\', '/', $file_path );

            if ( 0 !== strpos( $norm_path, $abs_path ) ) {
                return false;
            }

            $rel = ltrim( substr( $norm_path, strlen( $abs_path ) ), '/' );

            // فایل‌های wp-content یا wp-config فایل هسته قابل بازنویسی نیستند
            if ( 0 === strpos( $rel, 'wp-content/' ) || 'wp-config.php' === $rel || '.htaccess' === $rel ) {
                return false;
            }

            if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
                return true;
            }

            $root_core_files = [
                'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
                'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
                'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'
            ];

            return in_array( $rel, $root_core_files, true );
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
            $version = ! empty( $wp_version ) ? $wp_version : ( function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : '6.7' );

            $norm_path = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $file_path ) : str_replace( '\\', '/', $file_path );
            $abs_path  = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( ABSPATH ) : str_replace( '\\', '/', ABSPATH );

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

            // ۲. دانلود مستقیم فایل رسمی از مخازن معتبر (GitHub Raw و SVN رسمی WordPress.org با مکانیسم Failover)
            $urls_to_try = [
                "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/" . $relative_path,
                "https://core.svn.wordpress.org/tags/{$version}/" . $relative_path,
                "https://core.svn.wordpress.org/trunk/" . $relative_path,
            ];

            $official_content = null;
            $last_error = '';

            foreach ( $urls_to_try as $remote_url ) {
                $response = wp_remote_get( $remote_url, [
                    'timeout'    => 15,
                    'user-agent' => 'Gravity-Security-Restore/' . ( defined( 'HO_ANTI_VERSION' ) ? HO_ANTI_VERSION : '3.3.0' ),
                ] );

                if ( is_wp_error( $response ) ) {
                    $last_error = $response->get_error_message();
                    continue;
                }

                $status_code = wp_remote_retrieve_response_code( $response );
                if ( 200 !== $status_code ) {
                    $last_error = "کد وضعیت HTTP {$status_code}";
                    continue;
                }

                $body = wp_remote_retrieve_body( $response );
                if ( ! empty( $body ) ) {
                    $official_content = $body;
                    break;
                }
            }

            if ( empty( $official_content ) ) {
                return [
                    'success' => false,
                    'message' => 'دریافت نسخه رسمی فایل هسته از سرورهای WordPress.org ناموفق بود: ' . $last_error,
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
                'message'       => "فایل هسته ({$relative_path}) با موفقیت از منبع رسمی وردپرس بازگردانی شد.",
            ];
        }

        /**
         * بازگردانی فایل افزونه از مخزن رسمی WordPress.org Plugins SVN
         *
         * @param string $file_path مسیر کامل فایل افزونه
         * @param string $finding_id شناسه یافته
         * @return array
         */
        public static function restore_plugin_file_from_official( $file_path, $finding_id = '' ) {
            $norm_path    = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $file_path ) : str_replace( '\\', '/', $file_path );
            $plugins_dir  = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : ABSPATH . 'wp-content/plugins';
            $plugins_norm = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $plugins_dir ) : str_replace( '\\', '/', $plugins_dir );

            if ( 0 !== strpos( $norm_path, $plugins_norm ) ) {
                return [ 'success' => false, 'message' => 'فایل انتخابی در پوشه افزونه‌ها (plugins) قرار ندارد.' ];
            }

            $rel_plugin = ltrim( substr( $norm_path, strlen( $plugins_norm ) ), '/' );
            $parts      = explode( '/', $rel_plugin, 2 );
            if ( count( $parts ) < 2 ) {
                return [ 'success' => false, 'message' => 'فایل در ریشه پوشه افزونه‌ها قرار دارد و شناسه افزونه مشخص نیست.' ];
            }

            $slug    = $parts[0];
            $subpath = $parts[1];

            // استخراج نسخه افزونه از فایل اصلی افزونه
            $version          = '';
            $main_plugin_file = $plugins_norm . '/' . $slug . '/' . $slug . '.php';
            if ( ! file_exists( $main_plugin_file ) ) {
                $root_files = @glob( $plugins_norm . '/' . $slug . '/*.php' );
                if ( ! empty( $root_files ) ) {
                    foreach ( $root_files as $rf ) {
                        $hdr = @file_get_contents( $rf, false, null, 0, 4096 );
                        if ( false !== stripos( $hdr, 'Plugin Name:' ) ) {
                            $main_plugin_file = $rf;
                            break;
                        }
                    }
                }
            }

            if ( file_exists( $main_plugin_file ) ) {
                $hdr = @file_get_contents( $main_plugin_file, false, null, 0, 4096 );
                if ( preg_match( '/^[ \t\/*#@]*Version:\s*([0-9a-zA-Z.-]+)/mi', $hdr, $v_match ) ) {
                    $version = trim( $v_match[1] );
                }
            }

            // تلاش برای دانلود از SVN رسمی وردپرس
            $urls_to_try = [];
            if ( ! empty( $version ) ) {
                $urls_to_try[] = "https://plugins.svn.wordpress.org/{$slug}/tags/{$version}/{$subpath}";
            }
            $urls_to_try[] = "https://plugins.svn.wordpress.org/{$slug}/trunk/{$subpath}";

            $official_content = null;

            foreach ( $urls_to_try as $remote_url ) {
                $resp = wp_remote_get( $remote_url, [
                    'timeout'    => 15,
                    'user-agent' => 'Gravity-Security-PluginRestore/' . ( defined( 'HO_ANTI_VERSION' ) ? HO_ANTI_VERSION : '3.3.0' ),
                ] );

                if ( ! is_wp_error( $resp ) && 200 === wp_remote_retrieve_response_code( $resp ) ) {
                    $body = wp_remote_retrieve_body( $resp );
                    if ( ! empty( $body ) ) {
                        $syntax = self::validate_php_syntax( $body );
                        if ( $syntax['valid'] ) {
                            $official_content = $body;
                            break;
                        }
                    }
                }
            }

            if ( empty( $official_content ) ) {
                return [
                    'success' => false,
                    'message' => "نسخه رسمی این فایل برای افزونه ({$slug}) در مخزن رسمی WordPress.org یافت نشد (احتمالاً افزونه تجاری یا بومی است).",
                ];
            }

            // پشتیبان‌گیری در قرنطینه قبل از بازنویسی
            $backup_res = HO_Anti_Quarantine_Manager::quarantine_file(
                $file_path,
                "پشتیبان قبل از بازگردانی رسمی افزونه {$slug} از WordPress.org",
                'before_plugin_restore',
                $finding_id,
                false
            );

            if ( ! $backup_res['success'] ) {
                return [
                    'success' => false,
                    'message' => 'پشتیبان‌گیری در قرنطینه قبل از بازگردانی ناموفق بود: ' . $backup_res['message'],
                ];
            }

            $was_locked = ! is_writable( $file_path );
            if ( $was_locked ) {
                @chmod( $file_path, 0644 );
            }

            if ( false === @file_put_contents( $file_path, $official_content ) ) {
                return [ 'success' => false, 'message' => 'خطا در بازنویسی فایل روی دیسک.' ];
            }

            if ( get_option( 'ho_anti_files_locked', 1 ) ) {
                @chmod( $file_path, 0444 );
            }

            if ( class_exists( 'HO_Anti_Protection' ) ) {
                HO_Anti_Protection::record_security_event(
                    'plugin_file_restored',
                    "فایل افزونه ({$rel_plugin}) با نسخه رسمی WordPress.org جایگزین و ترمیم شد.",
                    [ 'file' => $rel_plugin, 'backup_id' => $backup_res['backup_id'] ]
                );
            }

            return [
                'success'       => true,
                'action'        => 'restored_from_plugin_repo',
                'backup_id'     => $backup_res['backup_id'],
                'relative_path' => $rel_plugin,
                'message'       => "فایل افزونه ({$rel_plugin}) با موفقیت از مخزن رسمی WordPress.org بازگردانی شد.",
            ];
        }

        /**
         * جراحی هدفمند و کنترل‌شده کدهای تزریقی با اعتبارسنجی نحوی و بازگردانی خودکار
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

            // ۱. جراحی تگ‌های اسکریپت تزریقی EtherHiding / Web3 C2 (در تگ یا در بدنه اسکریپت)
            $etherhiding_patterns = [
                '/<script\b(?:[^>]*?(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call|ethers(?:\.min)?\.js)[^>]*>.*?|[^>]*>(?:(?!<\/script>).)*?(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call|ethers(?:\.min)?\.js)(?:(?!<\/script>).)*?)<\/script>\s*/is',
                '/(?:echo|print)\s*\(?[\'"]<script\b(?:[^>]*?(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call|ethers(?:\.min)?\.js)[^>]*>.*?|[^>]*>(?:(?!<\/script>).)*?(?:polygon-bor-rpc|1rpc\.io|0xb29927B7D854b232D5E58CFc201866376E68C676|0x2cae8ae4|eth_call|ethers(?:\.min)?\.js)(?:(?!<\/script>).)*?)<\/script>[\'"]\)?\s*;?/is',
            ];
            foreach ( $etherhiding_patterns as $eh_pat ) {
                if ( preg_match( $eh_pat, $repaired_content ) ) {
                    $repaired_content = preg_replace( $eh_pat, '', $repaired_content );
                    $modifications[]  = 'حذف اسکریپت‌های تزریقی EtherHiding / Web3 C2';
                }
            }

            // ۲. جراحی گیت‌کیپرهای هدر (Header Gatekeepers / Cookie Lockers)
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

            // ۳. جراحی بلاک‌های eval و include مخرب تزریق‌شده در هدر فایل
            $eval_header_patterns = [
                '/<\?php\s*(?:\/\*[\s\S]*?\*\/|\/\/[^\r\n]*\r?\n)*\s*(?:@?ini_set\s*\([^;]*\)\s*;\s*)?(?:@?error_reporting\s*\([^;]*\)\s*;\s*)?(?:\$[a-zA-Z0-9_]+\s*=\s*[^;]+;\s*)*eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(.*?\)\s*\)\s*;?/is',
                '/<\?php\s*@?include(?:_once)?\s*\(?[\'"](?:\\\\x[0-9a-fA-F]{2}|\/tmp|\.cache|\.ico).*?[\'"]\)?\s*;?/is',
                '/<\?php\s*(?:\/\*[\s\S]*?\*\/|\/\/[^\r\n]*\r?\n)*\s*if\s*\(\s*!\s*defined\s*\([^)]+\)\s*\)\s*\{\s*eval\s*\([^}]+\}\s*;?/is',
            ];
            foreach ( $eval_header_patterns as $eh_pat ) {
                if ( preg_match( $eh_pat, $repaired_content ) ) {
                    $repaired_content = preg_replace( $eh_pat, "<?php\n", $repaired_content, 1 );
                    $modifications[]  = 'حذف بلاک ارزیابی پویای eval/include مخرب در هدر';
                    break;
                }
            }

            // ۴. جراحی کدهای الحاقی فوتر (Asset Flow / WP_Sys_Optimiser / Goto anchors)
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

            // ۵. در صورتی که جراحی مستقیم الگویی را حذف کرده باشد، اعتبارسنجی نحوی انجام می‌شود
            if ( ! empty( $modifications ) && $repaired_content !== $original_content ) {
                $syntax_res = self::validate_php_syntax( $repaired_content );
                if ( $syntax_res['valid'] ) {
                    // تهیه پشتیبان در قرنطینه با مانیفست
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

                    // تغییر موقت مجوز فایل قفل‌شده
                    $was_locked = ! is_writable( $file_path );
                    if ( $was_locked ) {
                        @chmod( $file_path, 0644 );
                    }

                    // نوشتن محتوای جراحی‌شده
                    if ( false === @file_put_contents( $file_path, $repaired_content ) ) {
                        return [
                            'success' => false,
                            'message' => 'خطا در ذخیره فایل جراحی‌شده بر روی سرور.',
                        ];
                    }

                    // قفل مجدد فایل به 0444
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
                        'message'       => 'فایل با موفقیت جراحی شد و کدهای مخرب بدون آسیب به عملکرد سایت پاک گردیدند (' . implode( '، ', $modifications ) . ').',
                    ];
                }
            }

            // ۶. اگر الگوی جراحی استاتیکی منطبق نشد، در صورتی که فایل متعلق به هسته است، تلاش برای بازگردانی از مخزن رسمی WordPress.org
            if ( self::is_core_file( $file_path ) ) {
                $core_res = self::restore_core_file_from_official( $file_path, $finding_id );
                if ( ! empty( $core_res['success'] ) ) {
                    return $core_res;
                }
            }

            // ۷. اگر متعلق به یک افزونه است، تلاش برای بازگردانی فایل از مخزن رسمی WordPress.org Plugins SVN
            $plugin_res = self::restore_plugin_file_from_official( $file_path, $finding_id );
            if ( ! empty( $plugin_res['success'] ) ) {
                return $plugin_res;
            }

            return [
                'success' => false,
                'message' => 'الگوی تزریقی شناخته‌شده‌ای در این فایل برای جراحی خودکار یافت نشد (نیازمند بازبینی دستی یا جایگزینی از نسخه اصلی سازنده).',
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Safe_Repair' ) ) {
        class_alias( 'HO_Anti_Safe_Repair', 'Gravity_Safe_Repair' );
    }
}
