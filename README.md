# Gravity Security & HO Anti Cleaner 🛡️
> **Enterprise-Grade Multi-Layer WordPress Security Suite, Safe Remediation Engine, Chunked Batch Scanner & Login Shield**  
> *Permanent Open-Source Defense Platform for WordPress and Web Hosts*

[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%20--%208.3-purple.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-GPL--2.0%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Version](https://img.shields.io/badge/Version-3.2.0-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen.svg)](#acceptance-tests)
[![Language](https://img.shields.io/badge/Documentation-English%20%7C%20Persian-blue.svg)](README_FA.md)

---

## 📖 Overview

**Gravity Security (HO Anti Cleaner)** is a production-grade, multi-layer security system engineered to prevent, detect, analyze, contain, and safely remediate WordPress infections, web shells, database injections, and host-level persistence.

Unlike conventional plugins that blindly delete suspicious files and break production websites, Gravity is built on a strict **"Repair Before Delete"** principle:
1. **Restore Official Code**: Restore modified WordPress core files directly from trusted official sources (`api.wordpress.org`).
2. **Surgical Precision**: Excise injected malware headers, backdoors, and footer hooks with PHP tokenizer syntax verification.
3. **Isolated Quarantine**: Encrypt and sandbox infected artifacts before any destructive operation, ensuring byte-by-byte rollback at any time.
4. **Chunked Batch Processing**: Scan large codebases in lightweight batches (150 files/chunk), preventing FastCGI / Nginx 504 Gateway Timeouts.
5. **Continuous Active Immunity**: Lock critical entrypoints to read-only (0444), block brute-force attacks, and sanitize dynamic outputs in real time.

---

## 🏗️ Architecture & Engines

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Gravity Security Suite                          │
├────────────────────────────────────────────────────────────────────────┤
│  [1] Active Protection Shield (Runtime & Entrypoint Defense)           │
│      ├── Micro-WAF (7G/8G-inspired parameter & cookie filtering)       │
│      ├── 0444 Immunity File Lock (wp-login.php, wp-config, index.php)  │
│      ├── Self-Healing Header Watchdog (Instant malware excision)       │
│      ├── Site URL Database Guard (Real-time hijacking interception)    │
│      ├── Real-time Frontend Output Sanitizer (EtherHiding neutralization)│
│      └── Login & Registration Shield (Honeypot, Rate Limiter, Anti-Enum)│
├────────────────────────────────────────────────────────────────────────┤
│  [2] Chunked Batch Scanner Coordinator                                 │
│      ├── Step 0: Persistence, DB, Rogue Users, Crons & Permissions     │
│      ├── Step 1: Official Core Checksum Verification & Rogue Core Files│
│      └── Step 2..N: Batched PHP Malware & Heuristic Inspection         │
├────────────────────────────────────────────────────────────────────────┤
│  [3] Safe Remediation Engine (Repair Before Delete)                    │
│      ├── Official Core Restore (Direct download from WordPress.org)    │
│      ├── Surgical Code Removal (PHP token validation; Zero WSOD)       │
│      └── Isolated Quarantine Sandboxing (.quarantine + AES Encrypted)  │
├────────────────────────────────────────────────────────────────────────┤
│  [4] Host-Level Security Agent (Linux Daemon)                          │
│      └── Python daemon (HMAC-SHA256, nice 19, LMD/ClamAV bridge)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Features

### 1. Chunked Batch Scanner (Zero Timeout Engine)
Monolithic scanners crash on servers with FastCGI or LiteSpeed execution limits (15–30s). Gravity utilizes a chunked state-machine batch scanner:
- Targets are collected in a single lightweight pre-pass.
- Files are processed in 150-file slices via asynchronous AJAX steps.
- Real-time progress bar with live file counts and step indicators.
- Automatic retry on transient network drops.

### 2. File Integrity & Official Core Checksums
- Connects directly to `api.wordpress.org/core/checksums/1.0/` for the exact WordPress version.
- Compares local file hashes (MD5) against official releases.
- Identifies modified core files (`CORE_FILE_MODIFIED`) with line-by-line diff viewing.
- Flags unreferenced/rogue PHP files inside `wp-admin` and `wp-includes` (e.g. fake plugins or list tables).
- One-click official restore with automatic quarantine backup.

### 3. Login & Anti-BruteForce Shield
- **IP Rate Limiting**: Tracks failed authentication attempts per IP. Automatically locks out attackers after 5 consecutive failures for 15 minutes.
- **Invisible Honeypot**: Deploys an invisible trap field (`ho_anti_hp_shield`) on `login_form` and `register_form`. Automated bot submissions are immediately blocked.
- **Author Enumeration Defense**: Intercepts `/?author=N` scans and REST API user harvesting (`/wp-json/wp/v2/users`) for unauthenticated visitors.
- **XML-RPC Hardening**: Disables `pingback.ping` reflection and multicall brute-force exploitation.

### 4. Advanced Threat Intel & Malware Heuristics
Synthesizing principles from leading open-source security projects (CleanTalk, Sucuri, 7G/8G Firewall, OWASP CRS, PHP-Malware-Finder):
- **Web Shells**: Detects WSO, c99, r57, b374k, Weevely, FilesMan, and custom obfuscated shells.
- **Dynamic Code Execution**: Detects nested `eval(gzinflate(base64_decode()))`, variable functions (`$$var()`), and hex-encoded character strings.
- **EtherHiding & Web3 C2**: Scans post content and options for blockchain-based smart contract RPC payloads (`eth_call`, `0x2cae8ae4`, `polygon-bor-rpc`, `1rpc.io`).
- **ClickFix Social Engineering**: Detects fake browser update popups and malicious PowerShell/MSHTA clipboards.
- **Rogue Persistence**: Detects malicious `mu-plugins`, hijacked drop-ins (`advanced-cache.php`, `db.php`), rogue admin accounts (`sys_*`), and scheduled WP-Cron tasks.

### 5. Active Anti-Injection & Self-Healing Watchdog
- **0444 Immunity Lock**: Changes file permissions of `wp-login.php`, `index.php`, `wp-config.php`, and `xmlrpc.php` to read-only (0444) to prevent PHP processes from writing code.
- **Self-Healing Guard**: If a cron job or external process re-injects a gatekeeper or `die();` block, Gravity detects the injection on the fly, strips it, restores valid code, and re-locks the file.
- **Site URL Guard**: Intercepts attempts to alter `siteurl` and `home` options via DB or filters, automatically reverting to trusted URLs.
- **Real-Time Output Sanitizer**: Buffers HTML responses on the frontend to strip EtherHiding and Web3 C2 scripts before reaching visitors' browsers.

### 6. Isolated Quarantine & Rollback
- Quarantined files are moved outside document root or into a protected directory (`.htaccess` / `web.config` denied).
- Files are encrypted and suffixed with `.quarantine`.
- JSON-based quarantine manifest tracks original permissions, file hashes, and parent paths.
- Instant, byte-for-byte rollback available directly from the admin dashboard.

---

## 📂 Project Structure

```text
├── ho-anti-cleaner/                     # WordPress Plugin Root
│   ├── ho-anti-cleaner.php              # Main Plugin Bootstrap (v3.2.0)
│   ├── emergency-cleaner.php            # Standalone Single-File Emergency Rescuer
│   ├── includes/
│   │   ├── models/
│   │   │   └── class-finding.php        # Gravity Standard Finding Model
│   │   ├── contracts/
│   │   │   └── interface-detection-adapter.php # Detection Adapter Interface
│   │   ├── remediation/
│   │   │   ├── class-quarantine-manager.php    # Sandboxed Quarantine & Rollback
│   │   │   └── class-safe-repair.php           # Surgical Repair & Official Core Restore
│   │   ├── engines/
│   │   │   ├── class-file-integrity-engine.php # Core Checksums & Diff Engine
│   │   │   ├── class-malware-engine.php        # YARA/Regex Token Analyzer
│   │   │   ├── class-persistence-engine.php    # DB, EtherHiding, Users & Crons
│   │   │   └── class-vulnerability-engine.php  # Outdated Component CVE Intelligence
│   │   ├── scanner/
│   │   │   └── class-batch-scanner.php         # Chunked Batch Scanner Coordinator
│   │   ├── host-agent/
│   │   │   └── class-host-agent-bridge.php     # Linux Server Daemon Bridge
│   │   ├── rules/
│   │   │   └── class-rule-manager.php          # Versioned Threat Rules Manager
│   │   ├── class-protection.php         # Active Shields, 0444 Lock, Login Guard
│   │   ├── class-scanner.php            # Full Scanner & Content Signatures
│   │   ├── class-cleaner.php            # Database & Artifact Remediation
│   │   ├── class-optimizer.php          # Security Health & DB Optimization
│   │   ├── class-ajax.php               # Nonce-Protected AJAX Controller
│   │   └── admin-view.php               # Modern Admin Dashboard View
│   └── assets/
│       ├── css/admin-style.css          # Responsive Admin Stylesheet
│       └── js/admin-script.js           # AJAX Batch Runner & UI Handlers
├── host-agent/                          # Standalone Linux Server Daemon
│   ├── gravity-agent.py                 # Python Daemon (HMAC-SHA256, LMD/ClamAV)
│   └── README.md                        # Linux Service Deployment Guide
├── tests/                               # Comprehensive Automated Test Suite
│   └── run-gravity-test-suite.php       # 24-Point Acceptance Test Runner
├── emergency-cleaner.php                # Standalone Web-Based Recovery Tool
├── README.md                            # English Documentation (This File)
└── README_FA.md                         # Persian Documentation (مستندات فارسی)
```

---

## 🚀 Installation & Usage

### Standard WordPress Installation
1. Download or clone this repository:
   ```bash
   git clone https://github.com/MehdiSabourii/ho-anti-cleaner.git
   ```
2. Copy the `ho-anti-cleaner` directory into your WordPress plugins directory:
   ```bash
   cp -r ho-anti-cleaner /path/to/wordpress/wp-content/plugins/
   ```
3. Activate the plugin via **WordPress Admin > Plugins > Installed Plugins > HO Anti Cleaner & Security Shield**.
4. Navigate to **HO Anti Shield** in the admin sidebar.
5. Click **شروع اسکن عمیق (Start Deep Scan)**.

### Standalone Emergency Recovery (Locked Out Site)
If a web shell or gatekeeper has locked you out of `wp-login.php`:
1. Upload `emergency-cleaner.php` to your WordPress root directory (next to `wp-config.php`).
2. Open `https://your-site.com/emergency-cleaner.php` in your browser.
3. The tool automatically surgically removes login gatekeepers, neutralizes `yrxc_u` cookies, repairs `wp-login.php`, cleans rogue drop-ins, and applies 0444 file locking.
4. **Delete `emergency-cleaner.php` immediately after recovery.**

---

## 🧪 Acceptance Tests

Gravity includes an isolated, self-contained test suite covering all engines, file locking, login shielding, EtherHiding sanitization, and rollback manifests:

```bash
php tests/run-gravity-test-suite.php
```

### Verified Test Matrix:
- **Test 1:** Standard Finding Model Contract Integrity
- **Test 2:** Quarantine Isolation & Encryption
- **Test 3:** Byte-by-Byte Rollback Verification
- **Test 4:** Surgical Header Repair (Excision without WSOD)
- **Test 5:** Surgical Footer Repair (Asset Flow Excision)
- **Test 6:** PHP Syntax Validator (Syntax Guard)
- **Test 7:** Official Core Checksum Verification (`api.wordpress.org`)
- **Test 8:** Core File Modified Detection (`CORE_FILE_MODIFIED`)
- **Test 9:** WSO / c99 / r57 Web Shell Detection
- **Test 10:** Multi-Stage Obfuscated PHP (`eval + base64 + gzinflate`)
- **Test 11:** Zero False Positive on Legitimate Code
- **Test 12:** Drop-In Persistence Detection (`advanced-cache.php`)
- **Test 13:** Hidden Rogue Administrator Detection (`sys_*`)
- **Test 14:** Malicious Cron Job Detection
- **Test 15:** Vulnerability Engine Fallback
- **Test 16:** Host Agent HMAC-SHA256 Authenticated Bridge
- **Test 17:** Chunked Batch Scanner Multi-Step Execution
- **Test 18:** EtherHiding Web3 C2 Detection in Database Posts
- **Test 19:** Real-Time Frontend Output Sanitizer
- **Test 20:** Official Core File Safe Deletion with Quarantine
- **Test 21:** Site URL Option Guard & Interception
- **Test 22:** Insecure Permissions Audit (0666 / 0777 Detection)
- **Test 23:** Strict Permission Hardening Enforcement (0644 / 0444)
- **Test 24:** Structured Security Event Logging & Persistence
- **Test 25:** Honeypot Bot Trap (Real-Time Login Blocker)
- **Test 26:** Brute-Force Rate Limiting & Temporary IP Lockout
- **Test 27:** Immediate Lockout Reset Upon Successful Authentication
- **Test 28:** Anti-User Enumeration (REST API Endpoint Filtering)

**Result: 28 of 28 tests pass (100% success rate).**

---

## 🤝 Contributing

We welcome community contributions, threat intelligence reports, and signature submissions!
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/new-threat-rule`).
3. Commit your changes (`git commit -am 'Add detection for emerging WebShell variant'`).
4. Ensure all test suite checks pass (`php tests/run-gravity-test-suite.php`).
5. Push to the branch (`git push origin feature/new-threat-rule`).
6. Open a Pull Request.

---

## 📄 License

This project is licensed under the **GNU General Public License v2.0 or later** (GPL-2.0+).  
Developed with passion by **ho mehdi sabour** and the Gravity Security community.
