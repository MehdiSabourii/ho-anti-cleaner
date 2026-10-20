<?php
/**
 * Rule and Definition Manager for Gravity Security & HO Anti Cleaner
 * مدیریت امن، نسخه‌بندی و به‌روزرسانی قواعد و امضاهای تشخیص بدافزار
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Rule_Manager' ) ) {

    class HO_Anti_Rule_Manager {

        const CURRENT_RULE_VERSION = '2.1.0';

        public static function get_active_rule_version() {
            return get_option( 'ho_anti_rule_version', self::CURRENT_RULE_VERSION );
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
                    'message' => 'اتصال به مخزن دریافت قواعد برقرار نشد؛ از قواعد پیش‌فرض محلی (نسخه ' . self::CURRENT_RULE_VERSION . ') استفاده می‌شود.',
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

            // اعتبارسنجی ارتقای نسخه
            if ( version_compare( $data['version'], self::get_active_rule_version(), '>' ) ) {
                update_option( 'ho_anti_custom_rules', $data['rules'], false );
                update_option( 'ho_anti_rule_version', $data['version'], false );
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
                'message' => 'قواعد سیستم در آخرین نسخه قرار دارد.',
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Rule_Manager' ) ) {
        class_alias( 'HO_Anti_Rule_Manager', 'Gravity_Rule_Manager' );
    }
}
