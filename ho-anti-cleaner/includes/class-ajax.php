<?php
/**
 * AJAX Handler for HO Anti Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Ajax_Handler' ) ) {

    class HO_Anti_Ajax_Handler {

        public function __construct() {
            add_action( 'wp_ajax_afc_scan_system',        [ $this, 'ajax_scan_system' ] );
            add_action( 'wp_ajax_afc_clean_database',     [ $this, 'ajax_clean_database' ] );
            add_action( 'wp_ajax_afc_clean_mu_plugins',   [ $this, 'ajax_clean_mu_plugins' ] );
            add_action( 'wp_ajax_afc_clean_uploads_php',  [ $this, 'ajax_clean_uploads_php' ] );
            add_action( 'wp_ajax_afc_repair_single_file', [ $this, 'ajax_repair_single_file' ] );
            add_action( 'wp_ajax_afc_repair_all_files',   [ $this, 'ajax_repair_all_files' ] );
            add_action( 'wp_ajax_afc_optimize_database',  [ $this, 'ajax_optimize_database' ] );
            add_action( 'wp_ajax_afc_generate_salts',     [ $this, 'ajax_generate_salts' ] );
            add_action( 'wp_ajax_afc_delete_single_file', [ $this, 'ajax_delete_single_file' ] );
        }

        private function verify_permissions() {
            $nonce = isset( $_POST['nonce'] ) ? $_POST['nonce'] : ( isset( $_REQUEST['nonce'] ) ? $_REQUEST['nonce'] : '' );
            if ( ! wp_verify_nonce( $nonce, 'afc_security_nonce' ) ) {
                wp_send_json_error( [
                    'message' => 'اعتبارسنجی توکن امنیتی (Nonce) منقضی شده است. لطفاً صفحه را رفرش (F5) کنید.'
                ] );
                exit;
            }

            if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'administrator' ) ) {
                wp_send_json_error( [
                    'message' => 'سطح دسترسی شما برای انجام این عملیات کافی نیست.'
                ] );
                exit;
            }
        }

        public function ajax_scan_system() {
            $this->verify_permissions();
            $scan_results = HO_Anti_Scanner::perform_full_scan();
            wp_send_json_success( $scan_results );
        }

        public function ajax_clean_database() {
            $this->verify_permissions();
            $result = HO_Anti_Cleaner::clean_database_artifacts();
            wp_send_json_success( $result );
        }

        public function ajax_clean_mu_plugins() {
            $this->verify_permissions();
            $result = HO_Anti_Cleaner::clean_mu_plugins();
            wp_send_json_success( $result );
        }

        public function ajax_clean_uploads_php() {
            $this->verify_permissions();
            $result = HO_Anti_Cleaner::clean_uploads_php();
            wp_send_json_success( $result );
        }

        private function normalize_incoming_path( $raw_path ) {
            if ( empty( $raw_path ) ) {
                return '';
            }
            $clean = str_replace( '\\', '/', (string) $raw_path );
            if ( function_exists( 'wp_normalize_path' ) ) {
                $clean = wp_normalize_path( $clean );
            }

            // اگر فایل مستقیماً پیدا شد
            if ( file_exists( $clean ) ) {
                return $clean;
            }

            // اگر مسیر نسبی ارسال شده است، افزودن ABSPATH
            $from_abs = wp_normalize_path( ABSPATH . ltrim( $clean, '/' ) );
            if ( file_exists( $from_abs ) ) {
                return $from_abs;
            }

            return $clean;
        }

        public function ajax_repair_single_file() {
            $this->verify_permissions();
            $raw = isset( $_POST['file_path'] ) ? $_POST['file_path'] : '';
            $file_path = $this->normalize_incoming_path( $raw );

            if ( empty( $file_path ) ) {
                wp_send_json_error( [ 'message' => 'مسیر فایل مشخص نشده است.' ] );
            }

            $res = HO_Anti_Cleaner::repair_single_file( $file_path );
            if ( ! empty( $res['success'] ) ) {
                wp_send_json_success( $res );
            } else {
                wp_send_json_error( $res );
            }
        }

        public function ajax_repair_all_files() {
            $this->verify_permissions();
            $files = isset( $_POST['files'] ) && is_array( $_POST['files'] ) ? $_POST['files'] : [];

            if ( empty( $files ) ) {
                wp_send_json_error( [ 'message' => 'هیچ فایلی برای ترمیم ارسال نشده است.' ] );
            }

            $repaired = 0;
            $deleted  = 0;
            $failed   = 0;
            $logs     = [];

            foreach ( $files as $raw_path ) {
                $path = $this->normalize_incoming_path( $raw_path );
                if ( ! empty( $path ) && file_exists( $path ) ) {
                    $res = HO_Anti_Cleaner::repair_single_file( $path );
                    if ( ! empty( $res['success'] ) ) {
                        if ( isset( $res['action'] ) && $res['action'] === 'deleted' ) {
                            $deleted++;
                            $logs[] = "حذف فایل بدافزار: " . basename( $path );
                        } else {
                            $repaired++;
                            $logs[] = "ترمیم موفق فایل: " . basename( $path );
                        }
                    } else {
                        $failed++;
                        $logs[] = "شکست در ترمیم: " . basename( $path ) . " (" . ( isset( $res['message'] ) ? $res['message'] : 'خطا' ) . ")";
                    }
                }
            }

            wp_send_json_success( [
                'repaired' => $repaired,
                'deleted'  => $deleted,
                'failed'   => $failed,
                'logs'     => $logs,
            ] );
        }

        public function ajax_optimize_database() {
            $this->verify_permissions();
            $result = HO_Anti_Optimizer::optimize_database();
            wp_send_json_success( $result );
        }

        public function ajax_generate_salts() {
            $this->verify_permissions();
            $salts = HO_Anti_Optimizer::generate_fresh_salts();
            wp_send_json_success( [ 'salts' => $salts ] );
        }

        public function ajax_delete_single_file() {
            $this->verify_permissions();
            $file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
            if ( empty( $file_path ) || ! file_exists( $file_path ) ) {
                wp_send_json_error( [ 'message' => 'فایل یافت نشد.' ] );
            }

            // فقط مجاز به حذف فایل‌های داخل wp-content
            $content_dir = realpath( WP_CONTENT_DIR );
            $real_file = realpath( $file_path );
            if ( false === $real_file || 0 !== strpos( $real_file, $content_dir ) ) {
                wp_send_json_error( [ 'message' => 'مسیر فایل خارج از wp-content است و مجاز به حذف نیست.' ] );
            }

            if ( @unlink( $real_file ) ) {
                wp_send_json_success( [ 'message' => 'فایل با موفقیت حذف شد.' ] );
            } else {
                wp_send_json_error( [ 'message' => 'امکان حذف فایل وجود ندارد (مجوز دسترسی را بررسی کنید).' ] );
            }
        }
    }

    if ( ! class_exists( 'AFC_Ajax_Handler' ) ) {
        class_alias( 'HO_Anti_Ajax_Handler', 'AFC_Ajax_Handler' );
    }
}
