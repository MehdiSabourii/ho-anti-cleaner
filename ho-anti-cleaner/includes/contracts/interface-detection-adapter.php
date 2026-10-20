<?php
/**
 * Detection Adapter Interface for Gravity Security & HO Anti Cleaner
 * رابط استاندارد موتورهای تشخیص تهدید
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! interface_exists( 'HO_Anti_Detection_Adapter_Interface' ) ) {

    interface HO_Anti_Detection_Adapter_Interface {

        /**
         * شناسه یکتای موتور (مانند: core_integrity, malware_signature, etc.)
         *
         * @return string
         */
        public function get_engine_id();

        /**
         * نام خوانا و توصیفی موتور
         *
         * @return string
         */
        public function get_engine_name();

        /**
         * نسخه فعلی موتور یا تعاریف قواعد
         *
         * @return string
         */
        public function get_engine_version();

        /**
         * بررسی آماده بودن و قابلیت اجرای موتور در محیط فعلی
         *
         * @return bool
         */
        public function is_available();

        /**
         * در صورت غیرفعال یا مسدود بودن موتور، دلیل شفاف را بازمی‌گرداند
         * (مانند: BLOCKED_ENVIRONMENT, API_UNREACHABLE, REQUIRES_SERVER_ACCESS)
         *
         * @return string
         */
        public function get_unavailability_reason();

        /**
         * اجرای اسکن روی اهداف مشخص شده
         *
         * @param array $targets آرایه‌ای از مسیرها، جداول یا المان‌های هدف
         * @param array $context اطلاعات زمینه اسکن (شناسه اسکن، گزینه‌ها و...)
         * @return HO_Anti_Finding[] آرایه‌ای از مدل‌های استاندارد یافته‌ها
         */
        public function scan( array $targets = [], array $context = [] );
    }

    if ( ! interface_exists( 'Gravity_Detection_Adapter_Interface' ) ) {
        // ایجاد نام مستعار برای سازگاری
        class_alias( 'HO_Anti_Detection_Adapter_Interface', 'Gravity_Detection_Adapter_Interface' );
    }
}
