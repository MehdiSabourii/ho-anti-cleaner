<?php
/**
 * Plugin Name: HO Anti Cleaner & Security Shield
 * Plugin URI:  https://wordpress.org
 * Description: ابزار پیشرفته ضد بدافزار، جراحی کدهای مخرب ورودی و گیت‌کیپرها، قفل ضد بازنویسی فایل‌ها و بهینه‌سازی دیتابیس وردپرس.
 * Version:     3.2.0
 * Author:      ho mehdi sabour
 * Author URI:  https://wordpress.org
 * Text Domain: ho-anti-cleaner
 * Domain Path: /languages
 * License:     GPL-2.0+
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// تعریف ایمن ثوابت افزونه
if ( ! defined( 'HO_ANTI_VERSION' ) )     define( 'HO_ANTI_VERSION', '3.2.0' );
if ( ! defined( 'HO_ANTI_PLUGIN_FILE' ) ) define( 'HO_ANTI_PLUGIN_FILE', __FILE__ );
if ( ! defined( 'HO_ANTI_PLUGIN_DIR' ) )  define( 'HO_ANTI_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
if ( ! defined( 'HO_ANTI_PLUGIN_URL' ) )  define( 'HO_ANTI_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

if ( ! defined( 'AFC_VERSION' ) )     define( 'AFC_VERSION', HO_ANTI_VERSION );
if ( ! defined( 'AFC_PLUGIN_FILE' ) ) define( 'AFC_PLUGIN_FILE', HO_ANTI_PLUGIN_FILE );
if ( ! defined( 'AFC_PLUGIN_DIR' ) )  define( 'AFC_PLUGIN_DIR', HO_ANTI_PLUGIN_DIR );
if ( ! defined( 'AFC_PLUGIN_URL' ) )  define( 'AFC_PLUGIN_URL', HO_ANTI_PLUGIN_URL );

// بارگذاری فایل‌های ماژولار و قراردادهای استاندارد Gravity
require_once HO_ANTI_PLUGIN_DIR . 'includes/models/class-finding.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/contracts/interface-detection-adapter.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/remediation/class-quarantine-manager.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/remediation/class-safe-repair.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-file-integrity-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-malware-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-persistence-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/engines/class-vulnerability-engine.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/scanner/class-batch-scanner.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/host-agent/class-host-agent-bridge.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/rules/class-rule-manager.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-protection.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-scanner.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-cleaner.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-optimizer.php';
require_once HO_ANTI_PLUGIN_DIR . 'includes/class-ajax.php';

if ( ! class_exists( 'HO_Anti_Cleaner_Plugin' ) ) {

    class HO_Anti_Cleaner_Plugin {

        private static $instance = null;
        public $direct_messages = [];

        public static function get_instance() {
            if ( null === self::$instance ) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        private function __construct() {
            // راه‌اندازی زودهنگام ماژول محافظت بلادرنگ و ضد تزریق
            HO_Anti_Protection::get_instance();

            // خنثی‌سازی زودهنگام درپشتی
            $this->early_neutralize_malware();

            // هوک‌های اصلی مدیریت
            add_action( 'admin_menu', [ $this, 'register_admin_menu' ] );
            add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
            add_action( 'admin_init', [ $this, 'handle_direct_post_actions' ] );

            // ثبت کنترلر AJAX
            new HO_Anti_Ajax_Handler();
        }

        private function early_neutralize_malware() {
            // خنثی‌سازی فیلترهای مخفی‌ساز بدافزار در حافظه (بدون حذف بی‌صدا از دیسک تا اسکنر بتواند آن را نمایش دهد)
            remove_all_filters( 'show_advanced_plugins' );
            remove_all_filters( 'all_plugins' );
        }

        public function handle_direct_post_actions() {
            if ( ! isset( $_POST['afc_direct_action'] ) ) {
                return;
            }

            if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'administrator' ) ) {
                return;
            }

            $action = sanitize_text_field( $_POST['afc_direct_action'] );

            if ( 'clean_all_direct' === $action ) {
                $db_res = HO_Anti_Cleaner::clean_database_artifacts();
                $mu_res = HO_Anti_Cleaner::clean_mu_plugins();
                $up_res = HO_Anti_Cleaner::clean_uploads_php();

                $scan = HO_Anti_Scanner::perform_full_scan();
                $repaired_files = 0;
                if ( ! empty( $scan['infected_files'] ) ) {
                    foreach ( $scan['infected_files'] as $inf ) {
                        $r = HO_Anti_Cleaner::repair_single_file( $inf['path'] );
                        if ( ! empty( $r['success'] ) ) {
                            $repaired_files++;
                        }
                    }
                }

                // قفل کردن خودکار فایل‌های حساس به 0444 جهت جلوگیری از تزریق مجدد
                HO_Anti_Protection::lock_critical_files();
                HO_Anti_Protection::install_execution_shields();

                $this->direct_messages[] = "عملیات پاک‌سازی کامل انجام شد: دیتابیس پاک شد، $repaired_files فایل آلوده ترمیم شدند، درپشتی‌های mu-plugins حذف شدند و کلیه فایل‌های اصلی به حالت ضد تزریق (0444) قفل گردیدند.";
            } elseif ( 'optimize_db_direct' === $action ) {
                $opt_res = HO_Anti_Optimizer::optimize_database();
                $this->direct_messages[] = "بهینه‌سازی دیتابیس انجام شد: " . implode( ' | ', $opt_res['report']['log'] );
            } elseif ( 'lock_files_direct' === $action ) {
                HO_Anti_Protection::lock_critical_files();
                $this->direct_messages[] = "کلیه فایل‌های حساس وردپرس (wp-login.php، index.php و...) با مجوز 0444 قفل شدند و نوشتن در آن‌ها ناممکن گردید.";
            } elseif ( 'unlock_files_direct' === $action ) {
                HO_Anti_Protection::unlock_critical_files();
                $this->direct_messages[] = "قفل فایل‌های حساس باز شد (مجوز 0644 برقرار گردید).";
            }
        }

        public function register_admin_menu() {
            $capability = current_user_can( 'manage_options' ) ? 'manage_options' : 'administrator';

            add_menu_page(
                'ضد بدافزار HO Anti',
                'ضد بدافزار HO Anti',
                $capability,
                'ho-anti-cleaner',
                [ $this, 'render_admin_dashboard' ],
                'dashicons-shield',
                75
            );
        }

        public function enqueue_admin_assets( $hook ) {
            if ( 'toplevel_page_ho-anti-cleaner' !== $hook ) {
                return;
            }

            wp_enqueue_style(
                'afc-admin-style',
                HO_ANTI_PLUGIN_URL . 'assets/css/admin-style.css',
                [],
                HO_ANTI_VERSION
            );

            wp_enqueue_script(
                'afc-admin-script',
                HO_ANTI_PLUGIN_URL . 'assets/js/admin-script.js',
                [ 'jquery' ],
                HO_ANTI_VERSION,
                true
            );

            wp_localize_script( 'afc-admin-script', 'afcData', [
                'ajax_url' => admin_url( 'admin-ajax.php' ),
                'nonce'    => wp_create_nonce( 'afc_security_nonce' ),
                'strings'  => [
                    'scanning'       => 'در حال اسکن عمیق سیستم و هسته...',
                    'repairing'      => 'در حال جراحی و ترمیم فایل‌ها...',
                    'optimizing'     => 'در حال بهینه‌سازی دیتابیس...',
                    'locking'        => 'در حال اعمال قفل محافظتی فایل‌ها...',
                    'unlocking'      => 'در حال باز کردن قفل فایل‌ها...',
                    'confirm_clean'  => 'آیا از پاک‌سازی موارد انتخاب شده مطمئن هستید؟ نسخه پشتیبان از فایل‌ها به صورت خودکار تهیه می‌شود.',
                    'confirm_all'    => 'توجه: این عملیات تمامی موارد آلوده شناسایی شده (کاربران مخفی، جداول، آپشن‌ها و کدهای تزریق شده در فایل‌ها) را پاک‌سازی و ترمیم می‌کند. ادامه می‌دهید؟',
                    'confirm_lock'   => 'فایل‌های حساس به حالت فقط خواندنی (0444) قفل می‌شوند و حتی پروسه‌های PHP هاست دسترسی بازنویسی نخواهند داشت. ادامه می‌دهید؟',
                    'clean_success'  => 'عملیات با موفقیت انجام شد.',
                    'error_occurred' => 'خطایی در ارتباط با سرور رخ داد.',
                ]
            ] );
        }

        public function render_admin_dashboard() {
            $direct_notices = $this->direct_messages;
            require_once HO_ANTI_PLUGIN_DIR . 'includes/admin-view.php';
        }
    }
}

// راه‌اندازی ایمن
add_action( 'plugins_loaded', [ 'HO_Anti_Cleaner_Plugin', 'get_instance' ] );
