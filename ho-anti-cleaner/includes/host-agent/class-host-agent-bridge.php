<?php
/**
 * Host Security Agent Bridge for Gravity Security & HO Anti Cleaner
 * رابط ارتباطی ایمن با Agent مستقل سروری و اعلام شفاف وضعیت هاست
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Host_Agent_Bridge' ) ) {

    class HO_Anti_Host_Agent_Bridge {

        const STATUS_NOT_INSTALLED       = 'not_installed';
        const STATUS_REQUIRES_SERVER_ACC = 'requires_server_access';
        const STATUS_CONNECTED           = 'connected';
        const STATUS_AUTH_FAILED         = 'auth_failed';

        /**
         * بررسی و دریافت وضعیت اتصال ایجنت سروری
         *
         * @return array
         */
        public static function get_agent_status() {
            $agent_token = get_option( 'ho_anti_host_agent_token', '' );
            $socket_path = '/run/gravity-agent/agent.sock';
            $status_file = '/var/log/gravity-agent/status.json';

            // ۱. بررسی محیط ویندوز یا نبود دسترسی سوکت سرور
            $is_windows = ( '\\' === DIRECTORY_SEPARATOR );
            if ( $is_windows ) {
                return [
                    'status'        => self::STATUS_REQUIRES_SERVER_ACC,
                    'is_active'     => false,
                    'label'         => 'غیرفعال (محیط ویندوز / نیازمند سرور لینوکس)',
                    'capabilities'  => [],
                    'details'       => 'ایجنت هاست اختصاصی سرورهای لینوکس با دسترسی Daemon است. در هاست اشتراکی یا ویندوز، امنیت در لایه وب و وردپرس تأمین می‌شود.',
                ];
            }

            // ۲. بررسی سوکت اختصاصی ایجنت
            if ( ! file_exists( $socket_path ) && ! file_exists( $status_file ) ) {
                return [
                    'status'        => self::STATUS_REQUIRES_SERVER_ACC,
                    'is_active'     => false,
                    'label'         => 'غیرفعال (نیازمند نصب ایجنت روی سرور)',
                    'capabilities'  => [],
                    'details'       => 'پوشش لایه هاست و فایل‌های خارج از ریشه سایت نیازمند نصب مستقل Gravity Host Agent بر روی سیستم‌عامل سرور است.',
                ];
            }

            // ۳. اگر فایل وضعیت یا سوکت موجود باشد و توکن اعتبارسنجی شده باشد
            if ( file_exists( $status_file ) && is_readable( $status_file ) ) {
                $raw = @file_get_contents( $status_file );
                $data = json_decode( $raw, true );

                if ( ! empty( $data ) && isset( $data['signature'] ) && ! empty( $agent_token ) ) {
                    $expected_sig = hash_hmac( 'sha256', $data['payload'], $agent_token );
                    if ( hash_equals( $expected_sig, $data['signature'] ) ) {
                        $payload = json_decode( $data['payload'], true );
                        return [
                            'status'       => self::STATUS_CONNECTED,
                            'is_active'    => true,
                            'label'        => 'متصل و فعال (پایش مداوم هاست)',
                            'version'      => isset( $payload['agent_version'] ) ? $payload['agent_version'] : '1.0.0',
                            'lmd_active'   => ! empty( $payload['lmd_active'] ),
                            'capabilities' => [
                                'host_filesystem_scan' => true,
                                'lmd_quarantine'       => ! empty( $payload['lmd_active'] ),
                                'outside_webroot_scan' => true,
                            ],
                            'details'      => 'ایجنت سروری با موفقیت متصل است و پایش لایه لینوکس و خارج از ریشه وب را پوشش می‌دهد.',
                        ];
                    } else {
                        return [
                            'status'    => self::STATUS_AUTH_FAILED,
                            'is_active' => false,
                            'label'     => 'خطای احراز اصالت توکن ایجنت',
                            'details'   => 'کلید توکن ثبت‌شده در وردپرس با امضای ایجنت سرور همخوانی ندارد.',
                        ];
                    }
                }
            }

            return [
                'status'    => self::STATUS_REQUIRES_SERVER_ACC,
                'is_active' => false,
                'label'     => 'غیرفعال (نیازمند پیکربندی توکن و دسترسی سرور)',
                'details'   => 'سرویس ایجنت کشف شد اما کلید اتصال متقابل در وردپرس پیکربندی نشده است.',
            ];
        }
    }

    if ( ! class_exists( 'Gravity_Host_Agent_Bridge' ) ) {
        class_alias( 'HO_Anti_Host_Agent_Bridge', 'Gravity_Host_Agent_Bridge' );
    }
}
