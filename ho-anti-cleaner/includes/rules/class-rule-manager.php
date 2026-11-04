<?php
/**
 * Rule and Definition Manager for Gravity Security & HO Anti Cleaner
 * مدیریت امن، نسخه‌بندی، پایگاه داده ۷۰۰+ قانون و مدیریت لیست سفید (Whitelisted URLs)
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Rule_Manager' ) ) {

    class HO_Anti_Rule_Manager {

        const CURRENT_RULE_VERSION = '3.5.0';

        private static $cached_rules = null;

        public static function get_active_rule_version() {
            return get_option( 'ho_anti_rule_version', self::CURRENT_RULE_VERSION );
        }

        /**
         * بارگذاری کلیه قوانین امنیتی (از دیتابیس یا فایل مرجع داخلی)
         *
         * @return array
         */
        public static function get_all_rules() {
            if ( null !== self::$cached_rules ) {
                return self::$cached_rules;
            }

            $custom_rules = get_option( 'ho_anti_custom_rules', null );
            if ( ! empty( $custom_rules ) && is_array( $custom_rules ) ) {
                self::$cached_rules = $custom_rules;
                return self::$cached_rules;
            }

            $db_file = __DIR__ . '/rules-database.php';
            if ( file_exists( $db_file ) ) {
                $rules = include $db_file;
                if ( is_array( $rules ) ) {
                    self::$cached_rules = $rules;
                    return self::$cached_rules;
                }
            }

            self::$cached_rules = [];
            return self::$cached_rules;
        }

        /**
         * دریافت خلاصه آماری قوانین بر اساس دسته‌بندی
         *
         * @return array
         */
        public static function get_categories_summary() {
            $rules = self::get_all_rules();
            $summary = [];

            foreach ( $rules as $r ) {
                $cat = isset( $r['category'] ) ? $r['category'] : 'general';
                if ( ! isset( $summary[ $cat ] ) ) {
                    $summary[ $cat ] = 0;
                }
                $summary[ $cat ]++;
            }

            arsort( $summary );
            return $summary;
        }

        /**
         * دریافت قوانین یک دسته‌بندی خاص
         *
         * @param string $category
         * @return array
         */
        public static function get_rules_by_category( $category ) {
            $rules = self::get_all_rules();
            if ( empty( $category ) || 'all' === $category ) {
                return $rules;
            }

            $filtered = [];
            foreach ( $rules as $r ) {
                if ( isset( $r['category'] ) && $r['category'] === $category ) {
                    $filtered[] = $r;
                }
            }

            return $filtered;
        }

        /**
         * بررسی فعال بودن یک قانون مشخص
         *
         * @param string $rule_id
         * @return bool
         */
        public static function is_rule_enabled( $rule_id ) {
            $disabled = get_option( 'ho_anti_disabled_rules', [] );
            if ( ! is_array( $disabled ) ) {
                $disabled = [];
            }
            return ! in_array( $rule_id, $disabled, true );
        }

        /**
         * فعال یا غیرفعال‌سازی یک قانون
         *
         * @param string $rule_id
         * @param bool $enable
         * @return bool
         */
        public static function toggle_rule( $rule_id, $enable ) {
            $disabled = get_option( 'ho_anti_disabled_rules', [] );
            if ( ! is_array( $disabled ) ) {
                $disabled = [];
            }

            if ( $enable ) {
                $disabled = array_diff( $disabled, [ $rule_id ] );
            } else {
                if ( ! in_array( $rule_id, $disabled, true ) ) {
                    $disabled[] = $rule_id;
                }
            }

            return update_option( 'ho_anti_disabled_rules', array_values( $disabled ) );
        }

        /**
         * دریافت لیست آدرس‌های مجاز (Whitelisted URLs)
         *
         * @return array
         */
        public static function get_whitelisted_urls() {
            $urls = get_option( 'ho_anti_whitelisted_urls', [] );
            if ( ! is_array( $urls ) ) {
                $urls = [];
            }

            // آدرس‌های پیش‌فرض مجاز
            $defaults = [
                '/wp-cron.php',
                '/wp-admin/async-upload.php',
            ];

            return array_unique( array_merge( $defaults, $urls ) );
        }

        /**
         * افزودن آدرس به لیست سفید
         *
         * @param string $url
         * @return bool
         */
        public static function add_whitelisted_url( $url ) {
            $url = trim( $url );
            if ( empty( $url ) ) return false;

            $urls = get_option( 'ho_anti_whitelisted_urls', [] );
            if ( ! is_array( $urls ) ) {
                $urls = [];
            }

            if ( ! in_array( $url, $urls, true ) ) {
                $urls[] = $url;
                return update_option( 'ho_anti_whitelisted_urls', array_values( $urls ) );
            }

            return true;
        }

        /**
         * حذف آدرس از لیست سفید
         *
         * @param string $url
         * @return bool
         */
        public static function remove_whitelisted_url( $url ) {
            $urls = get_option( 'ho_anti_whitelisted_urls', [] );
            if ( ! is_array( $urls ) ) {
                return false;
            }

            $urls = array_diff( $urls, [ $url ] );
            return update_option( 'ho_anti_whitelisted_urls', array_values( $urls ) );
        }

        /**
         * بررسی اینکه آیا آدرس درخواست فعلی در لیست سفید قرار دارد یا خیر
         *
         * @param string $req_uri
         * @return bool
         */
        public static function is_current_url_whitelisted( $req_uri = '' ) {
            if ( empty( $req_uri ) ) {
                $req_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
            }

            if ( empty( $req_uri ) ) {
                return false;
            }

            $whitelisted = self::get_whitelisted_urls();
            $path_only   = (string) wp_parse_url( $req_uri, PHP_URL_PATH );

            foreach ( $whitelisted as $wl ) {
                $wl = trim( $wl );
                if ( empty( $wl ) ) continue;

                // مطابقت کامل یا شروع مسیر
                if ( $path_only === $wl || 0 === strpos( $path_only, $wl ) || false !== strpos( $req_uri, $wl ) ) {
                    return true;
                }

                // پشتیبانی از عبارات باقاعده
                if ( 0 === strpos( $wl, '/' ) && substr( $wl, -1 ) === '/' && strlen( $wl ) > 2 ) {
                    if ( @preg_match( $wl, $req_uri ) ) {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * بررسی و به‌روزرسانی قواعد از مخزن امن
         */
        public static function check_for_rule_updates() {
            $remote_endpoint = apply_filters( 'ho_anti_rule_update_url', 'https://raw.githubusercontent.com/MehdiSabourii/ho-anti-cleaner/main/rules/definitions.json' );

            $response = wp_remote_get( $remote_endpoint, [
                'timeout'    => 10,
                'user-agent' => 'Gravity-Rule-Manager/' . HO_ANTI_VERSION,
            ] );

            if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
                return [
                    'success' => false,
                    'status'  => 'OFFLINE_MODE',
                    'message' => 'اتصال به مخزن دریافت قواعد برقرار نشد؛ از قواعد پیش‌فرض محلی (نسخه ' . self::CURRENT_RULE_VERSION . ') با موفقیت استفاده می‌شود.',
                ];
            }

            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );

            if ( empty( $data ) || ! isset( $data['version'] ) || ! isset( $data['rules'] ) ) {
                return [
                    'success' => false,
                    'status'  => 'INVALID_PAYLOAD',
                    'message' => 'پاسخ مخزن قواعد معتبر نیست.',
                ];
            }

            if ( version_compare( $data['version'], self::get_active_rule_version(), '>' ) ) {
                update_option( 'ho_anti_custom_rules', $data['rules'], false );
                update_option( 'ho_anti_rule_version', $data['version'], false );
                self::$cached_rules = $data['rules'];
                return [
                    'success'     => true,
                    'status'      => 'UPDATED',
                    'old_version' => self::get_active_rule_version(),
                    'new_version' => $data['version'],
                    'rules_count' => count( $data['rules'] ),
                ];
            }

            return [
                'success' => true,
                'status'  => 'UP_TO_DATE',
                'version' => self::get_active_rule_version(),
                'message' => 'قواعد سیستم در آخرین نسخه (نسخه ' . self::CURRENT_RULE_VERSION . ') قرار دارد.',
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Rule_Manager' ) ) {
        class_alias( 'HO_Anti_Rule_Manager', 'Gravity_Rule_Manager' );
    }
}
