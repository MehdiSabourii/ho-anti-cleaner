<?php
/**
 * Standard Finding Model for Gravity Security & HO Anti Cleaner
 * مدل استاندارد یافته‌های امنیتی مطابق الزامات Production-Grade
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Finding' ) ) {

    class HO_Anti_Finding implements JsonSerializable {

        /**
         * رده‌های طبقه‌بندی تهدید
         */
        const CLASSIFICATION_FILE_CHANGE        = 'file_change';           // تغییر فایل (لزوماً بدافزار نیست)
        const CLASSIFICATION_SUSPICIOUS         = 'suspicious_indicator';  // نشانه مشکوک نیازمند تحلیل
        const CLASSIFICATION_VULNERABILITY      = 'known_vulnerability';   // آسیب‌پذیری شناخته‌شده (نسخه آسیب‌پذیر)
        const CLASSIFICATION_CONFIRMED_MALWARE  = 'confirmed_malware';     // بدافزار یا وب‌شل قطعی

        /**
         * سطوح خطر (Severity)
         */
        const SEVERITY_INFO     = 'info';
        const SEVERITY_LOW      = 'low';
        const SEVERITY_MEDIUM   = 'medium';
        const SEVERITY_HIGH     = 'high';
        const SEVERITY_CRITICAL = 'critical';

        /**
         * سطوح قطعیت (Confidence)
         */
        const CONFIDENCE_LOW       = 'low';
        const CONFIDENCE_MEDIUM    = 'medium';
        const CONFIDENCE_HIGH      = 'high';
        const CONFIDENCE_CONFIRMED = 'confirmed';

        /**
         * اقدامات پیشنهادی اصلاح (Remediation Actions)
         */
        const ACTION_RESTORE_TRUSTED = 'restore_from_trusted_source';
        const ACTION_TARGETED_REPAIR = 'targeted_repair';
        const ACTION_QUARANTINE      = 'quarantine';
        const ACTION_MANUAL_REVIEW   = 'manual_review';
        const ACTION_SAFE_DELETE     = 'safe_delete';
        const ACTION_DELETE          = 'safe_delete'; // سازگاری با کدهای ارجاع‌دهنده
        const ACTION_UPDATE          = 'update_component';
        const ACTION_CLEAN_DB        = 'clean_database_record';

        /**
         * وضعیت اصلاح
         */
        const STATUS_UNREMEDIATED = 'unremediated';
        const STATUS_RESTORED     = 'restored';
        const STATUS_REPAIRED     = 'repaired';
        const STATUS_QUARANTINED  = 'quarantined';
        const STATUS_DELETED      = 'deleted';
        const STATUS_ROLLED_BACK  = 'rolled_back';
        const STATUS_FAILED       = 'failed';
        const STATUS_IGNORED      = 'ignored';

        // فیلدهای الزامی قرارداد
        public $id;
        public $scan_id;
        public $engine;
        public $rule_id;
        public $rule_version;
        public $threat_category;
        public $classification;
        public $target_type;
        public $target_path;
        public $evidence;
        public $severity;
        public $confidence;
        public $timestamp;
        public $local_hash;
        public $trusted_reference;
        public $recommended_action;
        public $remediation_status;
        public $rollback_reference;
        public $metadata;

        public function __construct( array $data = [] ) {
            $this->id                 = ! empty( $data['id'] ) ? $data['id'] : self::generate_finding_id();
            $this->scan_id            = ! empty( $data['scan_id'] ) ? $data['scan_id'] : 'scan_' . date( 'Ymd_His' );
            $this->engine             = ! empty( $data['engine'] ) ? $data['engine'] : 'generic';
            $this->rule_id            = ! empty( $data['rule_id'] ) ? $data['rule_id'] : 'UNKNOWN_RULE';
            $this->rule_version        = ! empty( $data['rule_version'] ) ? $data['rule_version'] : '1.0.0';
            $this->threat_category    = ! empty( $data['threat_category'] ) ? $data['threat_category'] : 'general';
            $this->classification     = ! empty( $data['classification'] ) ? $data['classification'] : self::CLASSIFICATION_SUSPICIOUS;
            $this->target_type        = ! empty( $data['target_type'] ) ? $data['target_type'] : 'file';
            $this->target_path        = ! empty( $data['target_path'] ) ? $data['target_path'] : '';
            $this->evidence           = isset( $data['evidence'] ) ? $data['evidence'] : [];
            $this->severity           = ! empty( $data['severity'] ) ? $data['severity'] : self::SEVERITY_MEDIUM;
            $this->confidence         = ! empty( $data['confidence'] ) ? $data['confidence'] : self::CONFIDENCE_MEDIUM;
            $this->timestamp          = ! empty( $data['timestamp'] ) ? $data['timestamp'] : current_time( 'mysql' );
            $this->local_hash         = ! empty( $data['local_hash'] ) ? $data['local_hash'] : null;
            $this->trusted_reference  = isset( $data['trusted_reference'] ) ? $data['trusted_reference'] : null;
            $this->recommended_action = ! empty( $data['recommended_action'] ) ? $data['recommended_action'] : self::ACTION_MANUAL_REVIEW;
            $this->remediation_status = ! empty( $data['remediation_status'] ) ? $data['remediation_status'] : self::STATUS_UNREMEDIATED;
            $this->rollback_reference = ! empty( $data['rollback_reference'] ) ? $data['rollback_reference'] : null;
            $this->metadata           = ! empty( $data['metadata'] ) ? $data['metadata'] : [];
        }

        public static function generate_finding_id() {
            return 'gfind_' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 16 );
        }

        public function to_array() {
            return [
                'id'                 => $this->id,
                'scan_id'            => $this->scan_id,
                'engine'             => $this->engine,
                'rule_id'            => $this->rule_id,
                'rule_version'       => $this->rule_version,
                'threat_category'    => $this->threat_category,
                'classification'     => $this->classification,
                'target_type'        => $this->target_type,
                'target_path'        => $this->target_path,
                'evidence'           => $this->evidence,
                'severity'           => $this->severity,
                'confidence'         => $this->confidence,
                'timestamp'          => $this->timestamp,
                'local_hash'         => $this->local_hash,
                'trusted_reference'  => $this->trusted_reference,
                'recommended_action' => $this->recommended_action,
                'remediation_status' => $this->remediation_status,
                'rollback_reference' => $this->rollback_reference,
                'metadata'           => $this->metadata,
            ];
        }

        #[\ReturnTypeWillChange]
        public function jsonSerialize() {
            return $this->to_array();
        }

        public function get_rule_id() {
            return $this->rule_id;
        }

        public function get_target_path() {
            return $this->target_path;
        }

        public function get_evidence() {
            return $this->evidence;
        }

        public function get_severity() {
            return $this->severity;
        }

        public static function from_array( array $data ) {
            return new self( $data );
        }
    }

    if ( ! class_exists( 'Gravity_Finding' ) ) {
        class_alias( 'HO_Anti_Finding', 'Gravity_Finding' );
    }
}
