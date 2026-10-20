<?php
/**
 * Batch & Chunk Processing Scanner Coordinator for Gravity Security & HO Anti Cleaner
 * هماهنگ‌کننده اسکن دسته‌ای و پله‌ای جهت جلوگیری از اتمام زمان اجرا (Timeout) و سرریز حافظه
 *
 * @package HO_Anti_Cleaner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'HO_Anti_Batch_Scanner' ) ) {

    class HO_Anti_Batch_Scanner {

        const BATCH_SIZE = 150; // تعداد فایل در هر پله اجرایی

        /**
         * آغاز فرآیند اسکن جدید و آماده‌سازی فهرست اهداف
         */
        public static function start_scan() {
            @ini_set( 'memory_limit', '512M' );

            $scan_id = 'scan_' . date( 'Ymd_His' ) . '_' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 6 );

            // گردآوری فهرست کامل فایل‌های هدف جهت اسکن
            $targets = self::collect_target_files();

            $total_files = count( $targets );
            $chunks      = array_chunk( $targets, self::BATCH_SIZE );
            $total_steps = count( $chunks ) + 2; // ۱ مرحله دیتابیس/ماندگاری + ۱ مرحله چکسام‌های هسته + پله‌های فایل‌ها

            $state = [
                'scan_id'       => $scan_id,
                'status'        => 'in_progress',
                'current_step'  => 0,
                'total_steps'   => $total_steps,
                'total_files'   => $total_files,
                'scanned_files' => 0,
                'findings'      => [],
                'chunks'        => $chunks,
                'created_at'    => current_time( 'mysql' ),
            ];

            $hour_seconds = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            set_transient( 'ho_anti_scan_state_' . $scan_id, $state, $hour_seconds );
            update_option( 'ho_anti_active_scan_id', $scan_id, false );

            return [
                'scan_id'     => $scan_id,
                'total_files' => $total_files,
                'total_steps' => $total_steps,
                'progress'    => 0,
            ];
        }

        /**
         * پردازش پله بعدی اسکن
         */
        public static function process_next_step( $scan_id ) {
            @ini_set( 'memory_limit', '512M' );
            @set_time_limit( 120 );

            $state = get_transient( 'ho_anti_scan_state_' . $scan_id );
            if ( empty( $state ) || ! is_array( $state ) ) {
                return [
                    'success' => false,
                    'message' => 'نشست اسکن یافت نشد یا منقضی شده است.',
                ];
            }

            $current_step = $state['current_step'];
            $total_steps  = $state['total_steps'];
            $findings     = isset( $state['findings'] ) ? $state['findings'] : [];

            // گام ۰: اسکن نقاط ماندگاری، دیتابیس و آسیب‌پذیری‌ها
            if ( 0 === $current_step ) {
                // موتور دیتابیس و ماندگاری
                if ( class_exists( 'HO_Anti_Persistence_Engine' ) ) {
                    $pers_engine = new HO_Anti_Persistence_Engine();
                    if ( $pers_engine->is_available() ) {
                        $pers_findings = $pers_engine->scan( [], [ 'scan_id' => $scan_id ] );
                        foreach ( $pers_findings as $f ) {
                            $findings[] = $f->to_array();
                        }
                    }
                }

                // موتور آسیب‌پذیری‌ها
                if ( class_exists( 'HO_Anti_Vulnerability_Engine' ) ) {
                    $vuln_engine = new HO_Anti_Vulnerability_Engine();
                    if ( $vuln_engine->is_available() ) {
                        $vuln_findings = $vuln_engine->scan( [], [ 'scan_id' => $scan_id ] );
                        foreach ( $vuln_findings as $f ) {
                            $findings[] = $f->to_array();
                        }
                    }
                }

                $state['current_step'] = 1;
                $state['findings']     = $findings;
                $hour_seconds = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            set_transient( 'ho_anti_scan_state_' . $scan_id, $state, $hour_seconds );

                $progress = round( ( 1 / $total_steps ) * 100, 1 );
                return [
                    'success'       => true,
                    'completed'     => false,
                    'scan_id'       => $scan_id,
                    'current_step'  => 1,
                    'total_steps'   => $total_steps,
                    'progress'      => $progress,
                    'scanned_files' => 0,
                    'findings_count'=> count( $findings ),
                ];
            }

            // گام ۱: اسکن یکپارچگی فایل‌های هسته (WordPress Core Checksums)
            if ( 1 === $current_step ) {
                if ( class_exists( 'HO_Anti_File_Integrity_Engine' ) ) {
                    $fie = new HO_Anti_File_Integrity_Engine();
                    if ( $fie->is_available() ) {
                        $core_findings = $fie->scan( [], [ 'scan_id' => $scan_id ] );
                        foreach ( $core_findings as $f ) {
                            $findings[] = $f->to_array();
                        }
                    }
                }

                $state['current_step'] = 2;
                $state['findings']     = $findings;
                $hour_seconds = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            set_transient( 'ho_anti_scan_state_' . $scan_id, $state, $hour_seconds );

                $progress = round( ( 2 / $total_steps ) * 100, 1 );
                return [
                    'success'       => true,
                    'completed'     => false,
                    'scan_id'       => $scan_id,
                    'current_step'  => 2,
                    'total_steps'   => $total_steps,
                    'progress'      => $progress,
                    'scanned_files' => 0,
                    'findings_count'=> count( $findings ),
                ];
            }

            // گام‌های بعدی: اسکن بسته‌ای فایل‌ها با موتور بدافزار و تحلیل معنایی
            $chunk_index = $current_step - 2;
            if ( isset( $state['chunks'][ $chunk_index ] ) ) {
                $batch_files = $state['chunks'][ $chunk_index ];

                if ( class_exists( 'HO_Anti_Malware_Engine' ) ) {
                    $malware_engine = new HO_Anti_Malware_Engine();
                    if ( $malware_engine->is_available() ) {
                        $batch_findings = $malware_engine->scan( $batch_files, [ 'scan_id' => $scan_id ] );
                        foreach ( $batch_findings as $f ) {
                            $findings[] = $f->to_array();
                        }
                    }
                }

                $state['scanned_files'] += count( $batch_files );
                $state['current_step']   = $current_step + 1;
                $state['findings']       = $findings;

                $is_last = ( $state['current_step'] >= $total_steps );
                if ( $is_last ) {
                    $state['status']       = 'completed';
                    $state['completed_at'] = current_time( 'mysql' );
                    // ذخیره گزارش نهایی
                    update_option( 'ho_anti_last_scan_report', [
                        'scan_id'       => $scan_id,
                        'completed_at'  => $state['completed_at'],
                        'total_files'   => $state['total_files'],
                        'findings'      => $findings,
                        'stats'         => self::compute_scan_statistics( $findings ),
                    ], false );
                }

                $hour_seconds = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            set_transient( 'ho_anti_scan_state_' . $scan_id, $state, $hour_seconds );

                $progress = min( 100, round( ( $state['current_step'] / $total_steps ) * 100, 1 ) );

                return [
                    'success'       => true,
                    'completed'     => $is_last,
                    'scan_id'       => $scan_id,
                    'current_step'  => $state['current_step'],
                    'total_steps'   => $total_steps,
                    'progress'      => $progress,
                    'scanned_files' => $state['scanned_files'],
                    'findings_count'=> count( $findings ),
                    'report'        => $is_last ? get_option( 'ho_anti_last_scan_report' ) : null,
                ];
            }

            return [
                'success'   => true,
                'completed' => true,
                'message'   => 'اسکن از قبل پایان یافته است.',
            ];
        }

        /**
         * محاسبه آمارهای تحلیلی و نمره‌دهی ترکیبی ریسک
         */
        public static function compute_scan_statistics( array $findings ) {
            $stats = [
                'total_threats'     => count( $findings ),
                'critical_count'    => 0,
                'high_count'        => 0,
                'medium_count'      => 0,
                'low_count'         => 0,
                'confirmed_malware' => 0,
                'file_changes'      => 0,
                'vulnerabilities'   => 0,
                'suspicious'        => 0,
                'risk_score'        => 0,
            ];

            foreach ( $findings as $f ) {
                $sev   = isset( $f['severity'] ) ? $f['severity'] : 'low';
                $class = isset( $f['classification'] ) ? $f['classification'] : '';

                if ( 'critical' === $sev ) {
                    $stats['critical_count']++;
                    $stats['risk_score'] += 25;
                } elseif ( 'high' === $sev ) {
                    $stats['high_count']++;
                    $stats['risk_score'] += 10;
                } elseif ( 'medium' === $sev ) {
                    $stats['medium_count']++;
                    $stats['risk_score'] += 4;
                } else {
                    $stats['low_count']++;
                    $stats['risk_score'] += 1;
                }

                if ( HO_Anti_Finding::CLASSIFICATION_CONFIRMED_MALWARE === $class ) {
                    $stats['confirmed_malware']++;
                } elseif ( HO_Anti_Finding::CLASSIFICATION_FILE_CHANGE === $class ) {
                    $stats['file_changes']++;
                } elseif ( HO_Anti_Finding::CLASSIFICATION_VULNERABILITY === $class ) {
                    $stats['vulnerabilities']++;
                } else {
                    $stats['suspicious']++;
                }
            }

            // سقف نمره ریسک ۱۰۰ است
            $stats['risk_score'] = min( 100, $stats['risk_score'] );

            return $stats;
        }

        /**
         * جمع‌آوری تمام فایل‌های PHP جهت اسکن بازگشتی
         */
        private static function collect_target_files() {
            $targets = [];
            $abs = wp_normalize_path( ABSPATH );

            // ۱. فایل‌های ریشه وردپرس
            $root_files = glob( $abs . '*.php' );
            if ( ! empty( $root_files ) ) {
                foreach ( $root_files as $rf ) {
                    $targets[] = wp_normalize_path( $rf );
                }
            }

            // ۲. فایل‌های wp-content
            $content_dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : $abs . 'wp-content';
            self::collect_dir_php_files( $content_dir, $targets );

            return array_unique( $targets );
        }

        private static function collect_dir_php_files( $dir, array &$targets ) {
            if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) return;

            $items = @scandir( $dir );
            if ( empty( $items ) ) return;

            $this_plugin = defined( 'HO_ANTI_PLUGIN_DIR' ) ? wp_normalize_path( HO_ANTI_PLUGIN_DIR ) : '';

            foreach ( $items as $it ) {
                if ( '.' === $it || '..' === $it ) continue;

                $full = wp_normalize_path( $dir . '/' . $it );

                // نادیده گرفتن خود افزونه و پوشه پشتیبان قرنطینه
                if ( ! empty( $this_plugin ) && ( $full === $this_plugin || 0 === strpos( $full, $this_plugin . '/' ) ) ) {
                    continue;
                }
                if ( false !== strpos( $full, 'afc-quarantine-backups' ) ) {
                    continue;
                }

                if ( is_dir( $full ) ) {
                    if ( in_array( $it, [ 'cache', 'node_modules', 'vendor' ], true ) ) {
                        continue;
                    }
                    self::collect_dir_php_files( $full, $targets );
                } elseif ( is_file( $full ) && 'php' === strtolower( pathinfo( $full, PATHINFO_EXTENSION ) ) ) {
                    $targets[] = $full;
                }
            }
        }
    }

    if ( ! class_exists( 'Gravity_Batch_Scanner' ) ) {
        class_alias( 'HO_Anti_Batch_Scanner', 'Gravity_Batch_Scanner' );
    }
}
