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
            add_action( 'wp_ajax_afc_scan_system',               [ $this, 'ajax_scan_system' ] );
            add_action( 'wp_ajax_afc_clean_database',            [ $this, 'ajax_clean_database' ] );
            add_action( 'wp_ajax_afc_clean_mu_plugins',          [ $this, 'ajax_clean_mu_plugins' ] );
            add_action( 'wp_ajax_afc_clean_uploads_php',         [ $this, 'ajax_clean_uploads_php' ] );
            add_action( 'wp_ajax_afc_repair_single_file',        [ $this, 'ajax_repair_single_file' ] );
            add_action( 'wp_ajax_afc_repair_all_files',          [ $this, 'ajax_repair_all_files' ] );
            add_action( 'wp_ajax_afc_optimize_database',         [ $this, 'ajax_optimize_database' ] );
            add_action( 'wp_ajax_afc_generate_salts',            [ $this, 'ajax_generate_salts' ] );
            add_action( 'wp_ajax_afc_delete_single_file',        [ $this, 'ajax_delete_single_file' ] );

            // اکشن‌های جدید سپر امنیتی و ضد تزریق (Anti-Injection Protection)
            add_action( 'wp_ajax_afc_toggle_file_lock',          [ $this, 'ajax_toggle_file_lock' ] );
            add_action( 'wp_ajax_afc_get_lock_status',           [ $this, 'ajax_get_lock_status' ] );
            add_action( 'wp_ajax_afc_toggle_self_healing',       [ $this, 'ajax_toggle_self_healing' ] );
            add_action( 'wp_ajax_afc_toggle_firewall',           [ $this, 'ajax_toggle_firewall' ] );
            add_action( 'wp_ajax_afc_toggle_login_protection',   [ $this, 'ajax_toggle_login_protection' ] );
            add_action( 'wp_ajax_afc_install_execution_shields', [ $this, 'ajax_install_execution_shields' ] );
            add_action( 'wp_ajax_afc_audit_cron_jobs',           [ $this, 'ajax_audit_cron_jobs' ] );
            add_action( 'wp_ajax_afc_clean_cron_jobs',           [ $this, 'ajax_clean_cron_jobs' ] );
            add_action( 'wp_ajax_afc_apply_wp_config_hardening', [ $this, 'ajax_apply_wp_config_hardening' ] );
            add_action( 'wp_ajax_afc_get_security_logs',          [ $this, 'ajax_get_security_logs' ] );
            add_action( 'wp_ajax_afc_clear_security_logs',        [ $this, 'ajax_clear_security_logs' ] );

            // اکشن‌های موتور استاندارد Gravity (Batch Scan, Rollback, Core Restore, Host Agent)
            add_action( 'wp_ajax_afc_batch_scan_start',          [ $this, 'ajax_batch_scan_start' ] );
            add_action( 'wp_ajax_afc_batch_scan_step',           [ $this, 'ajax_batch_scan_step' ] );
            add_action( 'wp_ajax_afc_quarantine_rollback',       [ $this, 'ajax_quarantine_rollback' ] );
            add_action( 'wp_ajax_afc_get_quarantine_manifest',   [ $this, 'ajax_get_quarantine_manifest' ] );
            add_action( 'wp_ajax_afc_restore_core_file',         [ $this, 'ajax_restore_core_file' ] );
            add_action( 'wp_ajax_afc_get_file_diff',             [ $this, 'ajax_get_file_diff' ] );
            add_action( 'wp_ajax_afc_get_host_agent_status',     [ $this, 'ajax_get_host_agent_status' ] );
            add_action( 'wp_ajax_afc_restore_siteurl',           [ $this, 'ajax_restore_siteurl' ] );
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

            if ( file_exists( $clean ) ) {
                return $clean;
            }

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
                        } elseif ( isset( $res['action'] ) && $res['action'] === 'repaired_header' ) {
                            $repaired++;
                            $logs[] = "جراحی هدر و حذف گیت‌کیپر لاگین: " . basename( $path );
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
            if ( empty( $file_path ) ) {
                wp_send_json_error( [ 'message' => 'مسیر فایل مشخص نشده است.' ] );
            }

            $normalized = $this->normalize_incoming_path( $file_path );
            if ( empty( $normalized ) || ! file_exists( $normalized ) ) {
                wp_send_json_error( [ 'message' => 'فایل در مسیر مشخص‌شده یافت نشد: ' . esc_html( $file_path ) ] );
            }

            // حذف امن فایل با پشتیبان‌گیری در قرنطینه
            $result = HO_Anti_Cleaner::delete_file_safely( $normalized, 'حذف فایل مخرب یا غیررسمی هسته به درخواست کاربر' );

            if ( $result['success'] ) {
                wp_send_json_success( $result );
            } else {
                wp_send_json_error( $result );
            }
        }

        public function ajax_restore_siteurl() {
            $this->verify_permissions();
            $target_url = isset( $_POST['target_url'] ) ? esc_url_raw( wp_unslash( $_POST['target_url'] ) ) : '';
            $result = HO_Anti_Cleaner::restore_tampered_siteurl( $target_url );

            if ( $result['success'] ) {
                wp_send_json_success( $result );
            } else {
                wp_send_json_error( $result );
            }
        }

        // ==========================
        // متدهای جدید سپر محافظتی
        // ==========================

        public function ajax_toggle_file_lock() {
            $this->verify_permissions();
            $lock_action = isset( $_POST['lock_action'] ) ? sanitize_text_field( $_POST['lock_action'] ) : 'lock';

            if ( 'lock' === $lock_action ) {
                $status = HO_Anti_Protection::lock_critical_files();
                wp_send_json_success( [
                    'locked'  => true,
                    'message' => 'کلیه فایل‌های حساس وردپرس با مجوز 0444 قفل شدند (ضد بازنویسی و تزریق).',
                    'files'   => $status,
                ] );
            } else {
                $status = HO_Anti_Protection::unlock_critical_files();
                wp_send_json_success( [
                    'locked'  => false,
                    'message' => 'قفل فایل‌های حساس باز شد (مجوز 0644 جهت به‌روزرسانی یا ویرایش قانونی).',
                    'files'   => $status,
                ] );
            }
        }

        public function ajax_get_lock_status() {
            $this->verify_permissions();
            $status = HO_Anti_Protection::get_lock_status();
            $is_locked = (bool) get_option( 'ho_anti_files_locked', 1 );
            wp_send_json_success( [
                'is_locked' => $is_locked,
                'files'     => $status,
            ] );
        }

        public function ajax_toggle_self_healing() {
            $this->verify_permissions();
            $enable = ! empty( $_POST['enable'] ) ? 1 : 0;
            update_option( 'ho_anti_self_healing_enabled', $enable );
            wp_send_json_success( [
                'enabled' => (bool) $enable,
                'message' => $enable ? 'محافظت خودترمیم‌کننده فعال شد.' : 'محافظت خودترمیم‌کننده غیرفعال شد.',
            ] );
        }

        public function ajax_toggle_firewall() {
            $this->verify_permissions();
            $enable = ! empty( $_POST['enable'] ) ? 1 : 0;
            update_option( 'ho_anti_firewall_enabled', $enable );
            wp_send_json_success( [
                'enabled' => (bool) $enable,
                'message' => $enable ? 'فایروال پیشگیرانه فعال شد.' : 'فایروال پیشگیرانه غیرفعال شد.',
            ] );
        }

        public function ajax_toggle_login_protection() {
            $this->verify_permissions();
            $enable = ! empty( $_POST['enable'] ) ? 1 : 0;
            update_option( 'ho_anti_login_protection_enabled', $enable );
            wp_send_json_success( [
                'enabled' => (bool) $enable,
                'message' => $enable ? 'سپر محافظت از ورود و ثبت‌نام فعال شد.' : 'سپر محافظت از ورود و ثبت‌نام غیرفعال شد.',
            ] );
        }

        public function ajax_install_execution_shields() {
            $this->verify_permissions();
            $res = HO_Anti_Protection::install_execution_shields();
            wp_send_json_success( $res );
        }

        public function ajax_audit_cron_jobs() {
            $this->verify_permissions();
            $res = HO_Anti_Protection::audit_cron_jobs();
            wp_send_json_success( $res );
        }

        public function ajax_clean_cron_jobs() {
            $this->verify_permissions();
            $res = HO_Anti_Protection::clean_suspicious_crons();
            wp_send_json_success( $res );
        }

        public function ajax_apply_wp_config_hardening() {
            $this->verify_permissions();
            $res = HO_Anti_Protection::apply_wp_config_hardening();
            if ( $res['success'] ) {
                wp_send_json_success( $res );
            } else {
                wp_send_json_error( $res );
            }
        }

        public function ajax_get_security_logs() {
            $this->verify_permissions();
            $logs = HO_Anti_Protection::get_security_logs();
            wp_send_json_success( [ 'logs' => $logs ] );
        }

        public function ajax_clear_security_logs() {
            $this->verify_permissions();
            HO_Anti_Protection::clear_security_logs();
            wp_send_json_success( [ 'message' => 'لاگ‌های امنیتی پاک‌سازی شدند.' ] );
        }

        public function ajax_batch_scan_start() {
            $this->verify_permissions();
            $res = HO_Anti_Batch_Scanner::start_scan();
            wp_send_json_success( $res );
        }

        public function ajax_batch_scan_step() {
            $this->verify_permissions();
            $scan_id = isset( $_POST['scan_id'] ) ? sanitize_text_field( $_POST['scan_id'] ) : '';
            if ( empty( $scan_id ) ) {
                wp_send_json_error( [ 'message' => 'شناسه اسکن نامعتبر است.' ] );
            }
            $res = HO_Anti_Batch_Scanner::process_next_step( $scan_id );
            wp_send_json_success( $res );
        }

        public function ajax_quarantine_rollback() {
            $this->verify_permissions();
            $backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( $_POST['backup_id'] ) : '';
            if ( empty( $backup_id ) ) {
                wp_send_json_error( [ 'message' => 'شناسه پشتیبان قرنطینه نامعتبر است.' ] );
            }
            $res = HO_Anti_Quarantine_Manager::rollback( $backup_id );
            if ( ! empty( $res['success'] ) ) {
                wp_send_json_success( $res );
            } else {
                wp_send_json_error( $res );
            }
        }

        public function ajax_get_quarantine_manifest() {
            $this->verify_permissions();
            $stats = HO_Anti_Quarantine_Manager::get_quarantine_stats();
            wp_send_json_success( $stats );
        }

        public function ajax_restore_core_file() {
            $this->verify_permissions();
            $raw = isset( $_POST['file_path'] ) ? $_POST['file_path'] : '';
            $file_path = $this->normalize_incoming_path( $raw );
            $finding_id = isset( $_POST['finding_id'] ) ? sanitize_text_field( $_POST['finding_id'] ) : '';
            $res = HO_Anti_Safe_Repair::restore_core_file_from_official( $file_path, $finding_id );
            if ( ! empty( $res['success'] ) ) {
                wp_send_json_success( $res );
            } else {
                wp_send_json_error( $res );
            }
        }

        public function ajax_get_file_diff() {
            $this->verify_permissions();
            $raw = isset( $_POST['file_path'] ) ? $_POST['file_path'] : '';
            $file_path = $this->normalize_incoming_path( $raw );
            $res = HO_Anti_File_Integrity_Engine::get_file_diff( $file_path );
            if ( ! empty( $res['success'] ) ) {
                wp_send_json_success( $res );
            } else {
                wp_send_json_error( $res );
            }
        }

        public function ajax_get_host_agent_status() {
            $this->verify_permissions();
            $res = HO_Anti_Host_Agent_Bridge::get_agent_status();
            wp_send_json_success( $res );
        }
    }

    if ( ! class_exists( 'AFC_Ajax_Handler' ) ) {
        class_alias( 'HO_Anti_Ajax_Handler', 'AFC_Ajax_Handler' );
    }
}
